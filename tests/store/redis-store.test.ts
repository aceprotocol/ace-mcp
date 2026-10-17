import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Redis } from 'ioredis';
import { ACEError, type ACEStore } from '@ace-protocol/sdk';
import { RedisStore, type RedisStoreOptions } from '../../src/store/redis-store.js';
import { SealedDataError, kekCipher } from '../../src/identity/kek.js';
import { toolErrorFromACE } from '../../src/errors.js';
import { identityKeys } from '../../src/store/keyspace.js';
import { REDIS } from '../helpers/stack.js';

const REDIS_URL = REDIS(44);
const ACE = 'ace:sha256:' + 'c'.repeat(64);
let redis: Redis;
beforeAll(() => { redis = new Redis(REDIS_URL); });
afterAll(() => redis.quit());
// Every store write is fenced by a live identity record (IdentityVault keeps it); these identities have one.
beforeEach(async () => {
  await redis.flushdb();
  for (const id of [ACE, 'ace:sha256:' + 'd'.repeat(64)]) await redis.hset(identityKeys(id).record, 'enc', 'x');
});

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array | null) => (b === null ? null : new TextDecoder().decode(b));

/** A value that fails to open surfaces as SealedDataError, which tools report as corrupt_record (not retryable). */
async function expectCorrupt(p: Promise<unknown>, aceId: string, key: string) {
  let err: unknown;
  try { await p; } catch (e) { err = e; }
  expect(err).toBeInstanceOf(SealedDataError);
  expect(err).toMatchObject({ aceId, key });
  const logged: object[] = [];
  const t = toolErrorFromACE(err, { error: (o) => { logged.push(o); } });
  expect(t).toMatchObject({ code: 'corrupt_record', retryable: false, message: 'a stored record could not be decrypted' });
  expect(logged).toEqual([{ code: 'corrupt_record', aceId, key }]);
}

async function expectCode(p: Promise<unknown>, code: string) {
  try { await p; } catch (e) { expect((e as ACEError).code).toBe(code); return; }
  throw new Error(`expected ${code}`);
}

const CIPHER = kekCipher(Buffer.alloc(32, 7));

describe('RedisStore', () => {
  const store = (aceId: string, opts: RedisStoreOptions = {}): RedisStore => new RedisStore(redis, aceId, CIPHER, opts);
  const make = (): ACEStore => store(ACE, { lockTtlMs: 2000, pollMs: 10 });
  it('read / write / delete / list', async () => {
    const s = make();
    expect(await s.read('a.json')).toBeNull();
    await s.write('a.json', enc('1'));
    await s.write('threads/x.json', enc('2'));
    await s.write('threads/y.json', enc('3'));
    await s.write('deliveries/z.json', enc('4'));
    await s.write('a.json', enc('5'));
    expect(dec(await s.read('a.json'))).toBe('5');
    expect(await s.list('threads/')).toEqual(['threads/x.json', 'threads/y.json']);
    expect(await s.list('')).toEqual(['a.json', 'deliveries/z.json', 'threads/x.json', 'threads/y.json']);
    expect(await s.list('thr')).toEqual(['threads/x.json', 'threads/y.json']);
    expect(await s.list('nope/')).toEqual([]);
    await s.delete('threads/x.json');
    await s.delete('threads/x.json'); // missing is not an error
    expect(await s.list('threads/')).toEqual(['threads/y.json']);
    expect(await s.read('threads/x.json')).toBeNull();
  });

  it('counts the sealed bytes it holds (write, overwrite, delete); a refused write counts nothing', async () => {
    const s = store(ACE);
    const strlen = async (key: string) => redis.strlen(identityKeys(ACE).storeValues + key);
    expect(await s.bytes()).toBe(0);
    await s.write('a.json', enc('12345'));
    await s.write('b.json', enc('1'));
    expect(await s.bytes()).toBe(await strlen('a.json') + await strlen('b.json'));
    await s.write('a.json', enc('1'.repeat(100)));
    expect(await s.bytes()).toBe(await strlen('a.json') + await strlen('b.json'));
    await s.delete('a.json'); await s.delete('a.json');
    expect(await s.bytes()).toBe(await strlen('b.json'));
    await s.delete('b.json');
    expect(await s.bytes()).toBe(0);
    await redis.hset(identityKeys(ACE).record, 'deleting', '1');
    await expect(store(ACE).write('c.json', enc('x'))).rejects.toThrow();
    expect(await s.bytes()).toBe(0);
  });

  it('writes and reads back an empty value', async () => {
    const s = make();
    await s.write('empty', new Uint8Array(0));
    const v = await s.read('empty');
    expect(v).not.toBeNull();
    expect(v!.length).toBe(0);
    expect(await s.list('')).toEqual(['empty']);
  });

  it('stores binary values exactly', async () => {
    const s = make();
    const bytes = new Uint8Array([0, 255, 128, 10, 13, 0]);
    await s.write('bin', bytes);
    expect(Array.from((await s.read('bin'))!)).toEqual(Array.from(bytes));
  });

  it('isolates identities', async () => {
    const a = make();
    const b = store('ace:sha256:' + 'd'.repeat(64));
    await a.write('x', enc('a'));
    expect(await b.read('x')).toBeNull();
    expect(await b.list('')).toEqual([]);
  });

  it('rejects invalid keys and lock names like the SDK stores', async () => {
    const s = make();
    await expectCode(s.write('../x', enc('1')), 'invalid_argument');
    await expectCode(s.read('A'), 'invalid_argument');
    // The SDK lock-name grammar ^[a-z0-9][a-z0-9_-]{0,63}$.
    for (const n of ['bad/name', 'a.b', '', '-a', 'A', 'x'.repeat(65), 'receive\n']) await expectCode(s.lock(n), 'invalid_argument');
    await (await s.lock('x'.repeat(64), { timeoutMs: 0 }))();
    await (await s.lock('a_b-c', { timeoutMs: 0 }))();
    // The SDK's own invalid-key table (sdk-ts/tests/store.test.ts).
    for (const k of ['', '/a', 'a/', 'A.json', '../x', 'a//b', '.hidden', 'x'.repeat(201), 'a b', 'value\n']) {
      await expectCode(s.write(k, enc('x')), 'invalid_argument');
      await expectCode(s.read(k), 'invalid_argument');
      await expectCode(s.delete(k), 'invalid_argument');
    }
    await expectCode(s.lock('receive', { timeoutMs: -1 }), 'invalid_argument');
    // Nothing is written that could not be read back (ACEStore: values ≤ 64 MiB).
    await expectCode(s.write('big', new Uint8Array(64 * 1024 * 1024 + 1)), 'invalid_argument');
    expect(await s.read('big')).toBeNull();
  });

  it('lock is exclusive, times out with lock_busy, and releases', async () => {
    const s = make();
    const release = await s.lock('receive', { timeoutMs: 0 });
    await expectCode(s.lock('receive', { timeoutMs: 50 }), 'lock_busy');
    const r2 = await s.lock('threads', { timeoutMs: 0 });
    await expectCode(make().lock('threads', { timeoutMs: 30 }), 'lock_busy');
    const held = await make().lock('threads', { timeoutMs: 0 }).catch((e: unknown) => e);
    expect(toolErrorFromACE(held)).toMatchObject({ code: 'busy', retryable: true });
    const busyReceive = await make().lock('receive', { timeoutMs: 0 }).catch((e: unknown) => e);
    expect(toolErrorFromACE(busyReceive)).toMatchObject({ code: 'busy', retryable: true });
    await r2();
    await release();
    await release(); // idempotent
    const again = await s.lock('receive', { timeoutMs: 0 });
    await again();
  }, 10_000);

  it('a waiter acquires once the holder releases', async () => {
    const s = make();
    const r1 = await s.lock('threads', { timeoutMs: 0 });
    const waiting = s.lock('threads', { timeoutMs: 2000 });
    setTimeout(() => { void r1(); }, 30);
    const r2 = await waiting;
    await r2();
  });

  it('renews a live receiver across several lease intervals', async () => {
    const s = store(ACE, { lockTtlMs: 180, pollMs: 10 });
    const release = await s.lock('receive', { timeoutMs: 0 });
    try {
      await new Promise(r => setTimeout(r, 650));
      await expectCode(make().lock('receive', { timeoutMs: 0 }), 'lock_busy');
      await s.write('value', enc('still-owner'));
    } finally { await release(); }
  });

  it('a crashed process lease expires without any unsafe client-side takeover', async () => {
    const key = identityKeys(ACE).locks + 'receive';
    await redis.set(key, 'dead-process-nonce', 'PX', 150, 'NX');
    const t = Date.now(), release = await make().lock('receive', { timeoutMs: 1000 });
    expect(Date.now() - t).toBeGreaterThanOrEqual(100);
    await release();
  });

  it('fences every stale operation and cannot free or borrow a replacement lock', async () => {
    const s = store(ACE, { lockTtlMs: 2000, pollMs: 10 });
    const stale = await s.lock('receive', { timeoutMs: 0 });
    await redis.del(identityKeys(ACE).locks + 'receive'); // Lease lost while the process is suspended.
    const replacement = make(), fresh = await replacement.lock('receive', { timeoutMs: 0 });
    await replacement.write('value', enc('fresh'));
    for (const action of [() => s.write('value', enc('stale')), () => s.read('value'), () => s.delete('value'), () => s.list('')]) {
      await expectCode(action(), 'storage_failed');
    }
    await stale();
    await expectCode(s.lock('receive', { timeoutMs: 0 }), 'storage_failed');
    await expectCode(make().lock('receive', { timeoutMs: 0 }), 'lock_busy');
    expect(dec(await replacement.read('value'))).toBe('fresh');
    await fresh();
  });

  it('an unrelated released lock does not invalidate another active lock', async () => {
    const s = make(), receive = await s.lock('receive'), threads = await s.lock('threads');
    await threads(); await s.write('value', enc('x')); await receive();
    expect(dec(await s.read('value'))).toBe('x');
  });

  it('maxWaitMs caps the caller timeout so a second receiver fails fast', async () => {
    const holder = make();
    const release = await holder.lock('receive', { timeoutMs: 0 });
    const s = store(ACE, { lockTtlMs: 2000, pollMs: 10, maxWaitMs: 100 });
    const t = Date.now();
    await expectCode(s.lock('receive', { timeoutMs: 10_000 }), 'lock_busy');
    expect(Date.now() - t).toBeLessThan(500);
    await release();
  });
});

describe('RedisStore namespace and unlock', () => {
  it('refuses a malformed aceId (it would become part of every key name)', () => {
    for (const bad of ['', 'ace:sha256:' + 'C'.repeat(64), 'ace:sha256:abc', 'x:*', 'ace:sha256:' + 'c'.repeat(64) + ':x']) {
      let err: unknown;
      try { new RedisStore(redis, bad, CIPHER); } catch (e) { err = e; }
      expect(err).toBeInstanceOf(ACEError);
      expect((err as ACEError).code).toBe('invalid_argument');
    }
  });

  it('a failed unlock permits cleanup but permanently stops this client', async () => {
    const client = new Redis(REDIS_URL);
    try {
      const s = new RedisStore(client, ACE, CIPHER, { pollMs: 10 });
      await (await s.lock('threads', { timeoutMs: 0 }))(); // defines the unlock script on this client
      const release = await s.lock('threads', { timeoutMs: 0 });
      const c = client as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
      const real = c.acemcp_store_unlock;
      c.acemcp_store_unlock = () => Promise.reject(new Error('connection reset'));
      await expectCode(release(), 'storage_failed');
      c.acemcp_store_unlock = real;
      await expectCode(s.lock('threads', { timeoutMs: 0 }), 'storage_failed'); // Poisoned even if the lock is still held
      await release(); // retry succeeds
      await expectCode(s.read('value'), 'storage_failed');
      await (await new RedisStore(client, ACE, CIPHER).lock('threads', { timeoutMs: 0 }))();
    } finally {
      await client.quit();
    }
  });
});

describe('RedisStore at-rest encryption', () => {
  it('round-trips through the cipher and never stores the plaintext', async () => {
    const s = new RedisStore(redis, ACE, CIPHER);
    await s.write('threads/t1.json', enc('{"secret":"the price is 42"}'));
    expect(dec(await s.read('threads/t1.json'))).toBe('{"secret":"the price is 42"}');
    const raw = await redis.getBuffer(`${identityKeys(ACE).storeValues}threads/t1.json`);
    expect(raw).not.toBeNull();
    expect(raw!.toString('latin1')).not.toContain('the price is 42');
    expect(raw!.length).toBe(12 + 16 + '{"secret":"the price is 42"}'.length);
  });

  it('a committed write with a lost response disables the old client', async () => {
    const client = new Redis(REDIS_URL);
    try {
      const s = new RedisStore(client, ACE, CIPHER);
      await s.write('warm', enc('x')); // defines the write script on this client
      type Fn = (...args: unknown[]) => Promise<unknown>;
      const commands = client as unknown as Record<string, Fn>, name = 'acemcp_store_writeBuffer';
      const original = commands[name]!.bind(client);
      let once = true;
      commands[name] = async (...args) => {
        const result = await original(...args);
        if (once) { once = false; throw Error('lost acknowledgement'); }
        return result;
      };
      await expectCode(s.write('value', enc('committed')), 'storage_failed');
      await expectCode(s.write('value', enc('retry')), 'storage_failed');
      expect(dec(await new RedisStore(redis, ACE, CIPHER).read('value'))).toBe('committed');
    } finally { await client.quit(); }
  });

  it('a value written under one KEK cannot be read under another', async () => {
    await new RedisStore(redis, ACE, CIPHER).write('a.json', enc('x'));
    const other = new RedisStore(redis, ACE, kekCipher(Buffer.alloc(32, 8)));
    await expectCorrupt(other.read('a.json'), ACE, 'a.json');
  });

  it('a tampered value is corrupt_record, not retryable storage_failed', async () => {
    const s = new RedisStore(redis, ACE, CIPHER);
    await s.write('a.json', enc('x'));
    const k = `${identityKeys(ACE).storeValues}a.json`;
    const blob = (await redis.getBuffer(k))!;
    blob[blob.length - 1] ^= 1;
    await redis.set(k, blob);
    await expectCorrupt(s.read('a.json'), ACE, 'a.json');
    await redis.set(k, blob.subarray(0, 10)); // shorter than any sealed value
    await expectCorrupt(s.read('a.json'), ACE, 'a.json');
  });

  it('a sealed value moved to another key or identity does not open', async () => {
    const s = new RedisStore(redis, ACE, CIPHER);
    await s.write('a.json', enc('x'));
    const blob = await redis.getBuffer(`${identityKeys(ACE).storeValues}a.json`);
    await redis.set(`${identityKeys(ACE).storeValues}b.json`, blob!);
    await expectCorrupt(s.read('b.json'), ACE, 'b.json');
    const D = 'ace:sha256:' + 'd'.repeat(64);
    await redis.set(`${identityKeys(D).storeValues}a.json`, blob!);
    await expectCorrupt(new RedisStore(redis, D, CIPHER).read('a.json'), D, 'a.json');
  });
});
