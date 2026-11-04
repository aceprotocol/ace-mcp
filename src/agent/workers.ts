import { setTimeout as pause } from 'node:timers/promises';
import { ACEError } from '@ace-protocol/sdk';
import type { AgentRuntime } from './runtime.js';
import type { IdentityVault } from '../identity/vault.js';
import type { ErrorLogger } from '../errors.js';
import { toolErrorFromACE } from '../errors.js';

export interface WorkerTiming {
  /** Identity discovery interval. */
  scanMs: number;
  /** Upkeep interval: identity check, descriptor/prekey rotation, due Outbox retries. */
  maintainMs: number;
  /** After capacity back-pressure the receiver stops (its Inbox snapshot drops journaled copies) and restarts this late. */
  fullRetryMs: number;
}

const DEFAULT_TIMING: WorkerTiming = { scanMs: 5000, maintainMs: 15_000, fullRetryMs: 30_000 };
/**
 * After `busy` (another process holds the identity's `receive` lock) the scan skips the identity this long: a start
 * decrypts and verifies the identity before it can find the lock taken. A crashed holder's lease expires in 60 s.
 */
const BUSY_RETRY_MS = 30_000;
/** After a `stop` notice the scan leaves the identity alone this long, unless its `start` notice comes first. */
const STOP_HOLD_MS = 30_000;
const code = (e: unknown) => toolErrorFromACE(e).code;
/**
 * The relay holds a newer key event log than ours (the owner imported the identity elsewhere, which re-keys it): this
 * copy's signing key is superseded, and retrying with it can never succeed.
 */
const superseded = (e: unknown) => e instanceof ACEError && e.relayCode === 'stale_seq';

/**
 * One resident receiver per hosted identity, so delivery does not depend on a model session. Each follows its relay
 * inbox over SSE through the SDK Inbox (verify, decrypt, admission, receipts, permit renewal, message log) and
 * periodically runs the SDK upkeep (`maintain`): republish the descriptor (rotating the prekey daily, registering on
 * demand), re-issue permits, retry due Outbox entries. A settings change (any process) stops the receiver before it
 * commits and restarts it after, through Redis pub/sub notices (AgentRuntime.onReceiverNotice).
 * A deletion aborts it through the runtime (the call is cancellable). A `stale_seq` answer (the identity was imported
 * and re-keyed elsewhere) stops it and marks the identity superseded, which takes it out of the scan.
 * The `receive` store lock fences it across processes. An identity being deleted (vault marker) is out of the scan
 * index and fails `vault.exists`, so no process starts its receiver and a running one ends its upkeep.
 */
export class AgentWorkers {
  readonly #tasks = new Map<string, { abort: AbortController; done: Promise<void> }>();
  /** Identities not to start before the given time: their receiver runs in another process, or their store is full. */
  readonly #notBefore = new Map<string, number>();
  readonly #timing: WorkerTiming;
  #stopped = false;
  #offset = 0;
  #timer?: ReturnType<typeof setTimeout>;
  #unsubscribe?: Promise<() => Promise<void>>;

  constructor(readonly runtime: AgentRuntime, readonly vault: IdentityVault, readonly logger: ErrorLogger, timing: Partial<WorkerTiming> = {}, readonly pageSize = 1000) {
    this.#timing = { ...DEFAULT_TIMING, ...timing };
  }

  async scan(): Promise<void> {
    if (this.#stopped) return;
    // Bounded, paginated enumeration; never decrypt every key at startup in one pass.
    const ids = await this.vault.listIdentities(this.#offset, this.pageSize);
    this.#offset = ids.length < this.pageSize ? 0 : this.#offset + ids.length;
    const now = Date.now();
    for (const id of ids) if (!this.#tasks.has(id) && !((this.#notBefore.get(id) ?? 0) > now)) this.#start(id);
  }

  /**
   * A settings change (any process) stops the identity's receiver before it commits (it waits for the `receive` lock)
   * and starts it again after, with the new settings.
   */
  #notice(notice: 'stop' | 'start', aceId: string): void {
    if (this.#stopped) return;
    const task = this.#tasks.get(aceId);
    if (notice === 'stop') {
      this.#notBefore.set(aceId, Date.now() + STOP_HOLD_MS);
      task?.abort.abort();
      return;
    }
    this.#notBefore.delete(aceId);
    if (!task) this.#start(aceId);
    else void task.done.then(() => { if (!this.#stopped && !this.#tasks.has(aceId)) this.#start(aceId); });
  }

  start(): void {
    this.#unsubscribe = this.runtime.onReceiverNotice((n, id) => this.#notice(n, id));
    this.#unsubscribe.catch((error: unknown) => this.logger.error({ error }, 'receiver notices unavailable'));
    const tick = async () => {
      try { await this.scan(); } catch (error) { this.logger.error({ error }, 'receiver discovery failed'); }
      if (!this.#stopped) { this.#timer = setTimeout(() => { void tick(); }, this.#timing.scanMs); this.#timer.unref(); }
    };
    void tick();
  }

  #start(aceId: string): void {
    const abort = new AbortController();
    const signal = abort.signal;
    const done = this.runtime.withIdentity(aceId, undefined, async (c) => {
      if (!c.provisioned) return;
      const client = await c.receiver();
      this.#notBefore.delete(aceId);
      this.runtime.receivers.add(aceId);
      const receive = (async () => {
        while (!signal.aborted) {
          let full = false;
          // The Inbox persists, answers and acknowledges; follow() ends on a deferral.
          for await (const out of client.follow({ signal })) full = out.kind === 'deferred' && out.error.code === 'receiver_capacity';
          if (full) {
            // Back-pressure (unread cap or byte cap): stop, so closing the Inbox snapshots it and drops the journaled
            // message copies, which no eviction reaches; the scan restarts the receiver after fullRetryMs.
            this.#notBefore.set(aceId, Date.now() + this.#timing.fullRetryMs);
            abort.abort();
            return;
          }
          // Any other deferral (e.g. a storage failure): resume after a pause.
          await pause(this.#timing.maintainMs, undefined, { signal }).catch(() => undefined);
        }
      })();
      // A receiver failure stops upkeep at once rather than leaving a live-looking zombie; the next scan restarts it,
      // unless the identity is superseded.
      // Never rejects: a failure to mark the identity (e.g. Redis down) is logged, and the receiver stops anyway.
      const stop = async (error: unknown) => {
        try {
          if (superseded(error)) {
            await this.vault.markSuperseded(aceId);
            this.logger.error({ aceId, code: 'stale_seq' }, 'the relay holds a newer key event log: receiver stopped, identity marked superseded');
          } else this.logger.error({ aceId, code: code(error) }, 'receiver stream failed');
        } catch (markError) {
          this.logger.error({ aceId, code: code(markError) }, 'could not mark the identity superseded; receiver stopped');
        } finally {
          abort.abort();
        }
      };
      receive.catch(stop);
      try {
        while (!signal.aborted) {
          if (!await this.vault.exists(aceId)) break;
          try {
            await client.maintain();
          } catch (error) {
            if (superseded(error)) { await stop(error); break; }
            this.logger.error({ aceId, code: code(error) }, 'receiver upkeep failed; retrying');
          }
          await pause(this.#timing.maintainMs, undefined, { signal }).catch(() => undefined);
        }
      } finally {
        abort.abort();
        await receive.catch(() => undefined);
        this.runtime.receivers.delete(aceId);
      }
    }, { touch: false, abort }).catch((error) => {
      // busy: another process runs it; unauthenticated: deleted (or being deleted) since the scan listed it.
      const c = code(error);
      if (c === 'busy') this.#notBefore.set(aceId, Date.now() + BUSY_RETRY_MS);
      else if (c !== 'unauthenticated') this.logger.error({ aceId, code: c }, 'receiver stopped');
    }).finally(() => this.#tasks.delete(aceId));
    this.#tasks.set(aceId, { abort, done });
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    clearTimeout(this.#timer);
    await (await this.#unsubscribe?.catch(() => undefined))?.();
    const tasks = [...this.#tasks.values()];
    tasks.forEach((t) => t.abort.abort());
    await Promise.allSettled(tasks.map((t) => t.done));
  }
}
