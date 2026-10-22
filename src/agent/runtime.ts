import type { Redis } from 'ioredis';
import { setTimeout as pause } from 'node:timers/promises';
import {
  ACEError, MessageLog, NetworkClient, RECEIVE_LOCK, RelayClient, StorePrekeyVault, canonicalStateBytes, publicRelay,
  type ACEStore, type SecretProtector, type SoftwareIdentity,
} from '@ace-protocol/sdk';
import type { McpConfig } from '../config.js';
import { McpToolError, unauthenticated, type ErrorLogger } from '../errors.js';
import type { IdentityRecord, IdentityVault } from '../identity/vault.js';
import { deriveSubkey, kekCipher } from '../identity/kek.js';
import { RedisStore } from '../store/redis-store.js';
import { RECEIVER_CHANNEL, identityKeys } from '../store/keyspace.js';
import {
  defaultSettings, hostedCard, loadSettings, saveSettings, settingsDigest, type HostedSettings,
} from './settings.js';

export interface AgentContext {
  aceId: string;
  identity: SoftwareIdentity;
  record: IdentityRecord;
  store: RedisStore;
  /**
   * The home relay client. Its registration ordering (07 § Registration) is persisted in `store` under the store
   * lock, so registrations stay strictly ordered across calls and replicas; once the deletion marker is set the store
   * refuses that write, so neither an explicit register nor the SDK's register-on-publish can reach the relay.
   */
  relay: RelayClient;
  settings: HostedSettings;
  /** False while the identity is still being provisioned (no settings saved yet; `settings` are the defaults). */
  provisioned: boolean;
  /**
   * The send-side client (publish, discover, connect, accept, block, send). It never receives (`receive: false`): the
   * resident worker owns the inbox, and this client never takes the `receive` lock nor touches inbox state.
   */
  network(): Promise<NetworkClient>;
  /** A receiving client (holds `receive`; `lock_busy` while a worker holds it). Closed when the call ends. */
  receiver(): Promise<NetworkClient>;
  /**
   * The one way to change the settings: under the identity's settings lock (a fenced store lock, so across processes),
   * stop its receiver wherever it runs and hold the `receive` lock, so no receiver applies the old policy from here
   * on; re-read the saved settings, apply `change` to them (it may throw, e.g. a scope check against the fresh state),
   * publish the descriptor and card record built from the result (the card gets the hosted tag), save it, then let the
   * receiver start again. The SDK's rules and the relay are the validation: a change the SDK or the relay refuses is
   * never saved.
   */
  updateSettings(change: (current: HostedSettings) => HostedSettings): Promise<HostedSettings>;
  /**
   * Unregister at the home relay (deletion and provisioning rollback). Its timestamp follows the ordering held in
   * `store` without persisting a new one, which a store under the deletion marker would refuse.
   */
  unregister(): Promise<void>;
}

export interface AgentRuntimeDeps {
  redis: Redis;
  vault: IdentityVault;
  config: McpConfig;
  /** The relay transport (tests inject one); every relay request goes through clientIpFetch around it. */
  fetch?: typeof fetch;
  logger?: ErrorLogger;
  /** How long a deletion waits for this identity's other in-flight calls in this process. Default 30 000. */
  drainMs?: number;
}

/**
 * `base` with `X-Forwarded-For: <ip>` on every request. The relay limits some routes per IP and every hosted
 * identity's traffic leaves from this container, so the relay (which trusts this service as a proxy) needs the end
 * client's IP. Workers send none: the relay limits listeners per identity, not per IP.
 */
export function clientIpFetch(base: typeof fetch, ip: string): typeof fetch {
  return (input, init) => {
    const headers = new Headers(init?.headers);
    headers.set('x-forwarded-for', ip);
    return base(input, { ...init, headers });
  };
}

/** Serializes every settings change of one identity (read, publish, save) across calls and processes. */
const SETTINGS_LOCK = 'mcp-settings';
/** How long a settings change waits for the identity's receivers (any process) to stop. */
const RECEIVER_STOP_MS = 15_000;
/**
 * How long an owner-API settings change waits for the settings lock: longer than one change in flight can hold it
 * (RECEIVER_STOP_MS plus the publish), and RedisStore's absolute cap. Tool calls keep the store's short default.
 */
const OWNER_SETTINGS_WAIT_MS = 30_000;

/** A receiver notice on RECEIVER_CHANNEL: `stop` before a settings change commits, `start` after it. */
export type ReceiverNotice = 'stop' | 'start';

/** One running withIdentity call; `ctx` is set once the identity has loaded. */
interface InFlight { ctx?: AgentContext; done: Promise<void>; abort?: AbortController }

export interface WithIdentityOptions {
  /** Record the call as identity use (lastUsedAt). Default true; workers pass false. */
  touch?: boolean;
  /** Makes the call cancellable: a deletion aborts it instead of waiting for it (resident receivers). */
  abort?: AbortController;
  /** An owner-API call: its settings changes wait longer and tool calls stand aside for them. Default false. */
  owner?: boolean;
}

/** `store` with its writes kept in memory: reads (and locks) are the store's, nothing is persisted. */
function readThrough(store: ACEStore): ACEStore {
  const written = new Map<string, Uint8Array | null>();
  return {
    read: async (key) => (written.has(key) ? written.get(key) ?? null : store.read(key)),
    write: async (key, value) => { written.set(key, value); },
    delete: async (key) => { written.set(key, null); },
    list: (prefix) => store.list(prefix),
    lock: (name, o) => store.lock(name, o),
  };
}

/** Seals the prekey vault document under the identity's `prekey` subkey of MCP_KEK. */
export function prekeyProtector(kek: Buffer, aceId: string): SecretProtector {
  const cipher = kekCipher(deriveSubkey(kek, 'prekey', aceId));
  const aad = `prekeys\0${aceId}`;
  return {
    seal: async (plain) => new Uint8Array(cipher.seal(aad, plain)),
    open: async (sealed) => new Uint8Array(cipher.open(aad, sealed)),
  };
}

/**
 * Runs one tool call (or one worker) as one hosted identity. The private key is decrypted from the vault per call and
 * the runtime keeps no reference to it once `fn` settles. JavaScript cannot zeroize the key bytes; dropping every
 * reference is the guarantee we can give.
 */
export class AgentRuntime {
  readonly #deps: AgentRuntimeDeps;
  readonly #kek: Buffer;
  /** Identities whose receiver runs in this process. */
  readonly receivers = new Set<string>();
  /** withIdentity calls running in this process, per identity, so a deletion can drain them. */
  readonly #inflight = new Map<string, Set<InFlight>>();

  constructor(deps: AgentRuntimeDeps) {
    this.#deps = deps;
    if (deps.config.kek.length !== 32) throw new Error('KEK must be 32 bytes');
    this.#kek = Buffer.from(deps.config.kek);
  }

  /**
   * The home relay client: signs for PUBLIC_RELAY_URL, connects to RELAY_URL, keeps the registration ordering in
   * `store`. With `ip`, forwards the client IP.
   */
  #homeRelay(store: ACEStore, ip?: string): RelayClient {
    const { config } = this.#deps;
    const base = this.#deps.fetch ?? globalThis.fetch.bind(globalThis);
    return new RelayClient(config.publicRelayUrl, { connectUrl: config.relayUrl, fetch: ip ? clientIpFetch(base, ip) : base, store });
  }

  #foreignRelay = (url: string): RelayClient => this.#deps.fetch ? new RelayClient(url, { fetch: this.#deps.fetch }) : publicRelay(url);

  get #messageLogOptions() {
    const { config } = this.#deps;
    return { maxUnread: config.maxUnreadMessages, retentionSeconds: config.messageRetentionDays * 86400 };
  }

  /**
   * The per-identity byte cap (both directions): when `need` more bytes would take the store past maxStoreBytes, read
   * messages are evicted, oldest first, to make room; when unread messages, the Outbox and state still leave none, it
   * throws `receiver_capacity`. Inbound, that leaves the packet on the relay (back-pressure) until the owner
   * acknowledges messages; outbound, the send is refused and nothing is stored.
   */
  async #makeRoom(store: RedisStore, need: number): Promise<void> {
    const max = this.#deps.config.maxStoreBytes;
    const over = await store.bytes() + need - max;
    if (over <= 0) return;
    let freed = 0, cutoff: number | undefined;
    for (const old of await new MessageLog(store, this.#messageLogOptions).list({ unreadOnly: false, limit: Number.MAX_SAFE_INTEGER })) {
      if (!old.read) continue;
      freed += canonicalStateBytes(old).length;
      cutoff = old.receivedAt + 1;
      if (freed >= over) break;
    }
    if (cutoff !== undefined) {
      // The message log's own retention purge with the cutoff as its clock: every read message received before it.
      const at = cutoff;
      await new MessageLog(store, { retentionSeconds: 0, clock: () => at }).list({ limit: 0 });
    }
    if (await store.bytes() + need > max) {
      throw new ACEError('receiver_capacity', 'this identity\'s storage is full: acknowledge messages to make room', { retryAfterSeconds: 30 });
    }
  }

  /** Open a NetworkClient for `settings`; `receive` takes the identity's inbox. */
  async open(identity: SoftwareIdentity, store: RedisStore, relay: RelayClient, settings: HostedSettings, mode: 'send' | 'receive'): Promise<NetworkClient> {
    const client = await NetworkClient.open({
      identity, store, relay, receive: mode === 'receive', profiles: [...settings.profiles, ...settings.manifests],
      vault: new StorePrekeyVault(store, { protect: prekeyProtector(this.#kek, identity.getACEId()) }),
      messageLog: this.#messageLogOptions, // A received message is stored twice until the next Inbox snapshot: its journal entry and the message log.
      checkCapacity: (m) => this.#makeRoom(store, 2 * canonicalStateBytes(m).length),
      card: settings.card, contact: settings.contact, listed: settings.listed, acceptProfiles: settings.acceptProfiles,
      ...(settings.handle ? { handle: settings.handle } : {}), ...(settings.pay ? { pay: settings.pay } : {}),
      ...(settings.ext ? { ext: settings.ext } : {}),
      delegations: settings.delegations, erc8004: settings.erc8004,
      foreignRelay: this.#foreignRelay,
    });
    // send() is the one Outbox write: the entry holds the body until the Outbox prunes it.
    const send = client.send.bind(client);
    client.send = async (to, type, body, o = {}) => {
      await this.#makeRoom(store, canonicalStateBytes({ to, type, body, ...o }).length);
      return send(to, type, body, o);
    };
    return client;
  }

  /** Tell every process's workers (RECEIVER_CHANNEL) to stop or start `aceId`'s receiver. */
  async #notify(notice: ReceiverNotice, aceId: string): Promise<void> {
    await this.#deps.redis.publish(RECEIVER_CHANNEL, `${notice} ${aceId}`);
  }

  /** Receive the notices of every process (a dedicated subscriber connection); the returned function ends it. */
  async onReceiverNotice(handler: (notice: ReceiverNotice, aceId: string) => void): Promise<() => Promise<void>> {
    const sub = this.#deps.redis.duplicate();
    sub.on('message', (_channel: string, message: string) => {
      const [notice, aceId] = message.split(' ');
      if ((notice === 'stop' || notice === 'start') && aceId) handler(notice, aceId);
    });
    await sub.subscribe(RECEIVER_CHANNEL);
    return async () => { await sub.quit().catch(() => sub.disconnect()); };
  }

  /**
   * Hold `store`'s `receive` lock: stop notices go out until every receiver of the identity (a resident worker or a
   * tool call's, in any process) has let go of it, for at most RECEIVER_STOP_MS (then `lock_busy`).
   */
  async #takeReceive(aceId: string, store: RedisStore): Promise<() => Promise<void>> {
    const deadline = Date.now() + RECEIVER_STOP_MS;
    for (;;) {
      await this.#notify('stop', aceId);
      try {
        return await store.lock(RECEIVE_LOCK, { timeoutMs: Math.max(0, deadline - Date.now()) });
      } catch (e) {
        if (!(e instanceof ACEError && e.code === 'lock_busy') || Date.now() >= deadline) throw e;
      }
    }
  }

  /**
   * End this identity's withIdentity calls in this process other than `self`'s: cancellable ones (resident receivers)
   * are aborted, then all are awaited (at most `drainMs`). Called by deletion after the vault marker is set: no new
   * call gets past vault.load, so this bounds the stragglers.
   */
  async drain(aceId: string, self: AgentContext): Promise<void> {
    const calls = [...this.#inflight.get(aceId) ?? []].filter((c) => c.ctx !== self);
    calls.forEach((c) => c.abort?.abort());
    const others = calls.map((c) => c.done);
    if (!others.length) return;
    const timer = new AbortController();
    await Promise.race([Promise.all(others), pause(this.#deps.drainMs ?? 30_000, undefined, { signal: timer.signal }).catch(() => undefined)]);
    timer.abort();
  }

  /**
   * Take the identity's settings lock. The owner always wins over tool calls (a client with only ace:configure must
   * not be able to lock its owner out by repeating ace_configure): while an owner change waits, it holds a counter
   * that makes every tool call's change fail `lock_busy` before and right after it gets the lock, so the owner waits
   * at most for the change already in flight (OWNER_SETTINGS_WAIT_MS covers one).
   */
  async #settingsLock(aceId: string, store: RedisStore, owner: boolean): Promise<() => Promise<void>> {
    const { redis } = this.#deps;
    const waiting = identityKeys(aceId).ownerWaiting;
    const ownerWaits = async () => Number(await redis.get(waiting) ?? 0) > 0;
    const yieldToOwner = () => new ACEError('lock_busy', 'the owner is changing this identity\'s settings', { retryAfterSeconds: 5 });
    if (!owner) {
      if (await ownerWaits()) throw yieldToOwner();
      const release = await store.lock(SETTINGS_LOCK);
      if (!(await ownerWaits())) return release;
      await release();
      throw yieldToOwner();
    }
    // The TTL outlives the wait, so a crashed process cannot leave tool calls locked out for long.
    await redis.multi().incr(waiting).pexpire(waiting, 2 * OWNER_SETTINGS_WAIT_MS).exec();
    try {
      return await store.lock(SETTINGS_LOCK, { timeoutMs: OWNER_SETTINGS_WAIT_MS }, OWNER_SETTINGS_WAIT_MS);
    } finally {
      await redis.decr(waiting);
    }
  }

  /** Load the identity, run `fn`, close whatever clients `fn` opened, drop the keys. */
  async withIdentity<T>(aceId: string, ip: string | undefined, fn: (ctx: AgentContext) => Promise<T>, o: WithIdentityOptions = {}): Promise<T> {
    // Tracked from entry (before load), so a deletion that sets its marker and then drains sees every call that may
    // have loaded the identity before the marker.
    let resolve!: () => void;
    const done = new Promise<void>((r) => { resolve = r; });
    const call: InFlight = { done, ...(o.abort ? { abort: o.abort } : {}) };
    const calls = this.#inflight.get(aceId) ?? new Set<InFlight>();
    this.#inflight.set(aceId, calls.add(call));
    try {
      return await this.#withIdentity(aceId, ip, fn, o.touch ?? true, o.owner ?? false, call);
    } finally {
      calls.delete(call);
      if (!calls.size && this.#inflight.get(aceId) === calls) this.#inflight.delete(aceId);
      resolve();
    }
  }

  async #withIdentity<T>(aceId: string, ip: string | undefined, fn: (ctx: AgentContext) => Promise<T>, touch: boolean, owner: boolean, call: InFlight): Promise<T> {
    const { redis, vault } = this.#deps;
    // Store reads are not fenced by the identity record, so the settings load needs no wait for the vault.
    const store = new RedisStore(redis, aceId, kekCipher(deriveSubkey(this.#kek, 'store', aceId)));
    const [loaded, saved] = await Promise.all([vault.load(aceId), loadSettings(store), touch ? vault.touch(aceId) : undefined]);
    if (!loaded) throw unauthenticated();
    const { identity, record } = loaded;
    const relay = this.#homeRelay(store, ip);
    let settings = saved ?? defaultSettings();
    /** The digest of the saved settings `settings` came from ('' for none). */
    let basis = settingsDigest(saved);
    const opened: NetworkClient[] = [];
    let send: Promise<NetworkClient> | undefined, receive: Promise<NetworkClient> | undefined;
    let settled = false;
    const live = (): void => {
      if (settled) throw new McpToolError('internal', 'agent context used after its call ended', false);
    };
    const track = async (p: Promise<NetworkClient>): Promise<NetworkClient> => { const h = await p; opened.push(h); return h; };
    const ctx: AgentContext = {
      aceId, identity, record, store, relay, settings, provisioned: saved !== null,
      network: () => { live(); return send ??= track(this.open(identity, store, relay, settings, 'send')); },
      receiver: () => {
        live();
        // Opened under the `receive` lock, which every settings change holds while it commits: if the saved settings
        // moved on since this call loaded them, reopen with them, so no receiver applies a superseded policy.
        return receive ??= track((async () => {
          for (;;) {
            const h = await this.open(identity, store, relay, settings, 'receive');
            const now = await loadSettings(store);
            if (settingsDigest(now) === basis) return h;
            await h.close();
            settings = ctx.settings = now ?? defaultSettings();
            basis = settingsDigest(now);
            send = undefined;
          }
        })());
      },
      updateSettings: async (change) => {
        live();
        const release = await this.#settingsLock(aceId, store, owner);
        try {
          const stopped = await this.#takeReceive(aceId, store);
          try {
            const next = change(await loadSettings(store) ?? settings);
            const s: HostedSettings = { ...next, card: hostedCard(next.card) };
            const client = await track(this.open(identity, store, relay, s, 'send'));
            await client.publish({ force: true });
            await saveSettings(store, s); // fenced by both locks: lands only while this call still holds them
            settings = ctx.settings = s;
            basis = settingsDigest(s);
            ctx.provisioned = true;
            send = Promise.resolve(client); // later network() calls use the new settings
            return s;
          } finally {
            await stopped();
            await this.#notify('start', aceId);
          }
        } finally {
          await release();
        }
      },
      unregister: async () => {
        live();
        await this.#homeRelay(readThrough(store), ip).unregister(identity);
      },
    };
    call.ctx = ctx;
    try {
      return await fn(ctx);
    } finally {
      settled = true;
      await Promise.all(opened.map((h) => h.close().catch(() => undefined)));
    }
  }
}
