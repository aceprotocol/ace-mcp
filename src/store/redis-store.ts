import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import type { Redis } from 'ioredis';
import { ACEError, checkKey, checkLockName, checkTimeout, checkValue, isACEId, lockTimeoutError, type ACEStore } from '@ace-protocol/sdk';
import { identityKeys } from './keyspace.js';
import { locateSealed, type KekCipher } from '../identity/kek.js';
import { luaScript, runScript, runScriptBuffer, type LuaScript } from './scripts.js';

// Compare-and-delete so a lock is released only by its holder.
const UNLOCK = luaScript('store_unlock', 1, `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0`);

// KEYS: value, key index, identity record, byte count, held locks...; ARGV: key, value, '', '' (pair with the record
// and the byte count), lock nonces...
// Check the lease in the same Redis command as each read/write. A timer alone cannot fence a
// suspended process. The local queue prevents a release/reacquire from changing these tokens
// while the command is in flight; uncertainty poisons the entire store instance.
const FENCE = `
for i = 5, #KEYS do
  if redis.call('GET', KEYS[i]) ~= ARGV[i] then return {0} end
end
`;
// A write lands only while the identity record exists and is not being deleted, so a straggling call (any process)
// cannot leave orphan data after IdentityVault.delete.
const GUARD = `
if redis.call('HEXISTS', KEYS[3], 'enc') == 0 or redis.call('HEXISTS', KEYS[3], 'deleting') == 1 then return {2} end
`;
const INDEX_TYPE = `local t = redis.call('TYPE', KEYS[2]).ok
if t ~= 'none' and t ~= 'set' then return redis.error_reply('invalid store index') end
`;
// Variable key count (the held locks): the caller passes numkeys first.
const READ = luaScript('store_read', undefined, FENCE + `return {1, redis.call('GET', KEYS[1])}`);
// The byte count (the sealed values' total length) moves in the same command as the value.
const WRITE = luaScript('store_write', undefined, FENCE + GUARD + INDEX_TYPE + `local old = redis.call('STRLEN', KEYS[1])
redis.call('SET', KEYS[1], ARGV[2]); redis.call('SADD', KEYS[2], ARGV[1]); redis.call('INCRBY', KEYS[4], #ARGV[2] - old); return {1}`);
const DELETE = luaScript('store_delete', undefined, FENCE + GUARD + INDEX_TYPE + `local old = redis.call('STRLEN', KEYS[1])
redis.call('DEL', KEYS[1]); redis.call('SREM', KEYS[2], ARGV[1]); if old > 0 then redis.call('DECRBY', KEYS[4], old) end; return {1}`);
const LIST = luaScript('store_list', undefined, FENCE + `return {1, redis.call('SMEMBERS', KEYS[2])}`);
const RENEW = luaScript('store_renew', undefined, `
for i = 1, #KEYS do if redis.call('GET', KEYS[i]) ~= ARGV[i + 1] then return 0 end end
for i = 1, #KEYS do redis.call('PEXPIRE', KEYS[i], ARGV[1]) end
return 1`);

export interface RedisStoreOptions {
  /** Renewed lease; a crashed holder frees it after this interval. Default 60 000. */
  lockTtlMs?: number;
  /** Lock acquisition poll interval. Default 50. */
  pollMs?: number;
  /** Upper bound on any caller's lock `timeoutMs`, so a second receiver fails fast. Default 2000. */
  maxWaitMs?: number;
}

/**
 * The SDK's ACEStore over Redis, namespaced per identity. Values are binary strings; a SET keeps
 * the exact key list so `list()` needs no SCAN. Locks are `SET NX PX` with a holder nonce, so a
 * crashed holder frees them after `lockTtlMs`. Live leases renew and every data operation is fenced.
 * Any uncertain Redis operation permanently disables this instance. Redis asynchronous failover
 * is not authoritative financial storage; use the SDK replicated coordinator for that. Values are AES-256-GCM sealed by `cipher` (the
 * runtime passes the identity's derived `store` subkey of the KEK; AAD `store\0<aceId>\0<key>`);
 * key names, the key index and locks stay plaintext.
 */
export class RedisStore implements ACEStore {
  readonly #redis: Redis;
  readonly #ns: string;
  readonly #keys: string;
  readonly #lockNs: string;
  readonly #record: string;
  readonly #bytes: string;
  readonly #lockTtlMs: number;
  readonly #pollMs: number;
  readonly #maxWaitMs: number;
  readonly #aceId: string;
  readonly #cipher: KekCipher;
  readonly #held = new Map<string, string>();
  #tail: Promise<unknown> = Promise.resolve();
  #timer?: ReturnType<typeof setTimeout>;
  #broken = false;

  constructor(redis: Redis, aceId: string, cipher: KekCipher, opts: RedisStoreOptions = {}) {
    // The aceId becomes part of every key name: only a well-formed one may build a namespace.
    if (!isACEId(aceId)) throw new ACEError('invalid_argument', 'invalid aceId');
    const k = identityKeys(aceId);
    this.#redis = redis;
    this.#ns = k.storeValues;
    this.#keys = k.storeKeys;
    this.#lockNs = k.locks;
    this.#record = k.record;
    this.#bytes = k.storeBytes;
    this.#lockTtlMs = opts.lockTtlMs ?? 60_000;
    this.#pollMs = opts.pollMs ?? 50;
    this.#maxWaitMs = opts.maxWaitMs ?? 2000;
    if (!Number.isSafeInteger(this.#lockTtlMs) || this.#lockTtlMs < 60 || this.#lockTtlMs > 300_000
      || !Number.isSafeInteger(this.#pollMs) || this.#pollMs < 1 || this.#pollMs > 10_000
      || !Number.isSafeInteger(this.#maxWaitMs) || this.#maxWaitMs < 0 || this.#maxWaitMs > 30_000) {
      throw new ACEError('invalid_argument', 'invalid store lease configuration');
    }
    this.#aceId = aceId;
    this.#cipher = cipher;
  }

  #aad(key: string): string {
    return `store\0${this.#aceId}\0${key}`;
  }

  #fail(what: string, e: unknown): ACEError {
    return new ACEError('storage_failed', `${what} failed`, { cause: e });
  }

  #queue<T>(body: () => Promise<T>): Promise<T> {
    const result = this.#tail.then(body); this.#tail = result.catch(() => undefined); return result;
  }
  #assert(): void { if (this.#broken) throw this.#fail('store', new Error('lock ownership or connection lost')); }
  #stopTimer(): void { clearTimeout(this.#timer); this.#timer = undefined; }
  #poison(): void { this.#broken = true; this.#stopTimer(); }
  #schedule(): void {
    if (this.#timer || this.#broken || !this.#held.size) return;
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      void this.#queue(async () => {
        if (this.#broken || !this.#held.size) return;
        try {
          const entries = [...this.#held];
          const result = await runScript(this.#redis, RENEW, entries.length, ...entries.map(([k]) => k), this.#lockTtlMs, ...entries.map(([, n]) => n));
          if (result !== 1) throw new Error('lock ownership lost');
          this.#schedule();
        } catch { this.#poison(); }
      });
    }, Math.max(1, Math.floor(this.#lockTtlMs / 3)));
    this.#timer.unref();
  }
  #operation(script: LuaScript, key = '', value: Buffer = Buffer.alloc(0)): Promise<unknown[]> {
    return this.#queue(async () => {
      this.#assert();
      try {
        const held = [...this.#held], keys = [this.#ns + key, this.#keys, this.#record, this.#bytes, ...held.map(([k]) => k)];
        const result = await runScriptBuffer(this.#redis, script, keys.length, ...keys, key, value, '', '', ...held.map(([, n]) => n));
        if (Array.isArray(result) && result[0] === 2) throw new Error('identity deleted');
        if (!Array.isArray(result) || result[0] !== 1) throw new Error('lock ownership lost');
        return result;
      } catch (e) { this.#poison(); throw this.#fail('store operation', e); }
    });
  }

  async read(key: string): Promise<Uint8Array | null> {
    const k = checkKey(key);
    const [, v] = await this.#operation(READ, k) as [number, Buffer | null];
    if (v === null) return null;
    // Wrong KEK, tampered value or a value moved to another key: a SealedDataError, not retryable,
    // so it is not wrapped as storage_failed. The tool layer maps it to `corrupt_record`.
    return locateSealed(this.#aceId, k, () => new Uint8Array(this.#cipher.open(this.#aad(k), v)));
  }

  async write(key: string, value: Uint8Array): Promise<void> {
    const k = checkKey(key);
    const stored = this.#cipher.seal(this.#aad(k), checkValue(value));
    await this.#operation(WRITE, k, stored);
  }

  async delete(key: string): Promise<void> {
    await this.#operation(DELETE, checkKey(key));
  }

  async list(prefix: string): Promise<string[]> {
    if (typeof prefix !== 'string') throw new ACEError('invalid_argument', 'prefix must be a string');
    const [, all] = await this.#operation(LIST) as [number, Buffer[]];
    return all.map(k => k.toString('utf8')).filter(k => k.startsWith(prefix)).sort();
  }

  /** The total length of the sealed values this identity's store holds (the per-identity byte cap counts it). */
  async bytes(): Promise<number> {
    return Number(await this.#redis.get(this.#bytes) ?? 0);
  }

  /**
   * `maxWaitMs` replaces the instance's cap for this one call (at most 30 000): the service's own long waits (an owner
   * settings change). The SDK never passes it, so its locks keep the instance cap.
   */
  async lock(name: string, opts: { timeoutMs?: number } = {}, maxWaitMs = this.#maxWaitMs): Promise<() => Promise<void>> {
    checkLockName(name);
    if (!Number.isSafeInteger(maxWaitMs) || maxWaitMs < 0 || maxWaitMs > 30_000) throw new ACEError('invalid_argument', 'invalid lock wait cap');
    const timeoutMs = Math.min(checkTimeout(opts.timeoutMs), maxWaitMs);
    const key = this.#lockNs + name; // acemcp:lock:<aceId>:<name>
    const nonce = randomUUID();
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const ok = await this.#queue(async () => {
        this.#assert();
        if (this.#held.has(key)) return false; // Never borrow a successor's token on this instance.
        try {
          if (await this.#redis.set(key, nonce, 'PX', this.#lockTtlMs, 'NX') !== 'OK') return false;
          this.#held.set(key, nonce); this.#schedule(); return true;
        } catch (e) { this.#poison(); throw this.#fail('lock', e); }
      });
      if (ok) break;
      const left = deadline - Date.now();
      if (left <= 0) throw lockTimeoutError(name); // lock_busy
      await sleep(Math.min(this.#pollMs, left));
    }
    let released = false;
    return () => this.#queue(async () => {
      if (released) return;
      // Cleanup may be retried after a lost ACK, but a poisoned instance can never resume data I/O.
      try {
        const deleted = await runScript(this.#redis, UNLOCK, key, nonce);
        if (deleted !== 1 && !this.#broken) { this.#poison(); throw new Error('lock ownership lost'); }
        released = true; this.#held.delete(key);
        if (!this.#held.size) this.#stopTimer();
      } catch (e) { this.#poison(); throw this.#fail('unlock', e); }
    });
  }
}
