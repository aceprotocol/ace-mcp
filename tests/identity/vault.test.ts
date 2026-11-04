import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { SoftwareIdentity } from '@ace-protocol/sdk';
import { Redis } from 'ioredis';
import { IdentityNotFoundError, IdentityVault } from '../../src/identity/vault.js';
import { RedisStore } from '../../src/store/redis-store.js';
import { identityKeys } from '../../src/store/keyspace.js';
import { sha256Hex } from '@ace-protocol/sdk';
import { generateToken, isTokenShape } from '../../src/identity/token.js';
import { SealedDataError, deriveSubkey, kekCipher, kekId } from '../../src/identity/kek.js';
import { REDIS } from '../helpers/stack.js';
import { toolErrorFromACE } from '../../src/errors.js';

let redis: Redis;
const KEK = Buffer.alloc(32, 9);
beforeAll(() => { redis = new Redis(REDIS(45)); });
afterAll(() => redis.quit());
beforeEach(() => redis.flushdb());

describe('token', () => {
  it('has the documented shape and hashes deterministically', () => {
    const { token, hash } = generateToken();
    expect(token).toMatch(/^ace_mcp_[A-Za-z0-9_-]{43}$/);
    expect(isTokenShape(token)).toBe(true);
    expect(isTokenShape('ace_mcp_short')).toBe(false);
    expect(sha256Hex(token)).toBe(hash);
  });
});

describe('IdentityVault', () => {
  it('creates, resolves by token, loads the same keys, and never stores the token or plaintext seeds', async () => {
    const v = new IdentityVault(redis, KEK, () => 1000);
    const { identity, token } = await v.create();
    const aceId = identity.getACEId();
    expect(await v.resolveToken(token)).toBe(aceId);
    expect(await v.resolveToken('ace_mcp_' + 'x'.repeat(43))).toBeNull();
    expect((await v.load(aceId))!.identity.exportPrivateKey()).toEqual(identity.exportPrivateKey());
    const row = await redis.hgetall('acemcp:identity:' + aceId);
    expect(Object.keys(row).sort()).toEqual(['createdAt', 'enc', 'kid', 'lastUsedAt', 'tokenHash']);
    expect(row.kid).toBe(kekId(KEK));
    const dump = JSON.stringify(row);
    expect(dump).not.toContain(token);
    const exp = identity.exportPrivateKey();
    for (const seed of [exp.rootSeed, exp.nextRootSeed!, exp.signingSeed]) expect(dump).not.toContain(seed);
  });

  it('seals under the identity subkey (not the KEK itself), bound to the aceId', async () => {
    const v = new IdentityVault(redis, KEK);
    const { identity } = await v.create();
    const aceId = identity.getACEId();
    const enc = Buffer.from((await redis.hget('acemcp:identity:' + aceId, 'enc'))!, 'base64');
    expect(() => kekCipher(KEK).open(`identity\0${aceId}`, enc)).toThrow(SealedDataError);
    expect(JSON.parse(kekCipher(deriveSubkey(KEK, 'identity', aceId)).open(`identity\0${aceId}`, enc).toString()).signingSeed).toBe(identity.exportPrivateKey().signingSeed);
  });

  it('a record sealed under another KEK names the KEK mismatch and is corrupt_record', async () => {
    const v = new IdentityVault(redis, KEK);
    const { identity } = await v.create();
    const err = await new IdentityVault(redis, Buffer.alloc(32, 8)).load(identity.getACEId()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SealedDataError);
    expect((err as Error).message).toMatch(/another KEK/);
    const logged: object[] = [];
    expect(toolErrorFromACE(err, { error: (o) => { logged.push(o); } })).toMatchObject({ code: 'corrupt_record', retryable: false });
    expect(logged).toEqual([{ code: 'corrupt_record', aceId: identity.getACEId(), key: 'identity' }]);
  });

  it('rejects a truncated blob, a blob moved to another aceId and an invalid export', async () => {
    const v = new IdentityVault(redis, KEK);
    const a = (await v.create()).identity;
    const b = (await v.create()).identity.getACEId();
    await redis.hset('acemcp:identity:' + b, 'enc', (await redis.hget('acemcp:identity:' + a.getACEId(), 'enc'))!);
    await expect(v.load(b)).rejects.toThrow(/could not be decrypted/);
    const id = a.getACEId();
    const reseal = (plaintext: unknown) => redis.hset('acemcp:identity:' + id, 'enc',
      kekCipher(deriveSubkey(KEK, 'identity', id)).seal(`identity\0${id}`, typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext)).toString('base64'));
    const exp = a.exportPrivateKey();
    for (const bad of [{ ...exp, kel: [] }, { ...exp, kel: (await SoftwareIdentity.generate()).getKel() }, 'not json']) {
      await reseal(bad);
      expect(toolErrorFromACE(await v.load(id).catch((e: unknown) => e))).toMatchObject({ code: 'corrupt_record' });
    }
    await redis.hset('acemcp:identity:' + id, 'enc', Buffer.alloc(20).toString('base64'));
    await expect(v.load(id)).rejects.toThrow(/too short/);
  });

  it('rotates the token, marks export, and does not create stub records for unknown identities', async () => {
    const v = new IdentityVault(redis, KEK);
    const { identity, token } = await v.create();
    const t2 = await v.rotateToken(identity.getACEId());
    expect(await v.resolveToken(token)).toBeNull();
    expect(await v.resolveToken(t2)).toBe(identity.getACEId());
    await v.markExported(identity.getACEId());
    expect((await v.load(identity.getACEId()))!.record.exportedAt).toBeTypeOf('number');
    await redis.flushdb();
    const ghost = 'ace:sha256:' + 'f'.repeat(64);
    await expect(v.rotateToken(ghost)).rejects.toBeInstanceOf(IdentityNotFoundError);
    await expect(v.markExported(ghost)).rejects.toBeInstanceOf(IdentityNotFoundError);
    await v.touch(ghost);
    expect(await redis.keys('acemcp:*')).toEqual([]);
  });

  it('delete removes every key of the identity: token, store values, grants, rate buckets, record, index entry', async () => {
    const v = new IdentityVault(redis, KEK);
    const id = (await v.create()).identity.getACEId();
    const k = identityKeys(id);
    await new RedisStore(redis, id, kekCipher(Buffer.alloc(32, 1))).write('messages/m1.json', new Uint8Array([1]));
    await redis.set(k.toolRate, '3', 'EX', 60);
    await redis.set(k.ownerRate, '1', 'EX', 60);
    await redis.zadd(k.grants, 9999999999, 'g1');
    await redis.set('acemcp:oauth:grant:g1', '{}');
    await v.delete(id);
    expect(await redis.keys('acemcp:*')).toEqual([]);
    expect(await v.load(id)).toBeNull();
    await expect(v.rotateToken(id)).rejects.toBeInstanceOf(IdentityNotFoundError);
  });

  it('a deletion marker makes the identity gone everywhere until cancelled; guarded store writes are refused', async () => {
    const v = new IdentityVault(redis, KEK, () => 1000);
    const { identity, token } = await v.create();
    const id = identity.getACEId();
    const store = new RedisStore(redis, id, kekCipher(Buffer.alloc(32, 1)));
    await store.write('a', new Uint8Array([1]));
    await v.beginDelete(id);
    await expect(v.beginDelete(id)).rejects.toBeInstanceOf(IdentityNotFoundError); // one deletion at a time
    expect(await v.load(id)).toBeNull();
    expect(await v.exists(id)).toBe(false);
    expect(await v.resolveToken(token)).toBeNull();
    expect(await v.ownerHash(id)).toBeNull();
    expect(await v.listIdentities()).toEqual([]);
    await expect(store.write('b', new Uint8Array([2]))).rejects.toMatchObject({ code: 'storage_failed' });

    await v.cancelDelete(id);
    expect(await v.exists(id)).toBe(true);
    expect(await v.resolveToken(token)).toBe(id);
    expect(await v.listIdentities()).toEqual([id]);
    await new RedisStore(redis, id, kekCipher(Buffer.alloc(32, 1))).write('b', new Uint8Array([2]));

    await v.beginDelete(id);
    await v.delete(id);
    expect(await redis.keys('acemcp:*')).toEqual([]);
    await expect(new RedisStore(redis, id, kekCipher(Buffer.alloc(32, 1))).write('c', new Uint8Array([3])))
      .rejects.toMatchObject({ code: 'storage_failed' });
    expect(await redis.keys('acemcp:*')).toEqual([]);
  });

  it('a superseded identity stays loadable but leaves the scan index, also across a cancelled deletion', async () => {
    const v = new IdentityVault(redis, KEK, () => 1000);
    const { identity } = await v.create();
    const id = identity.getACEId();
    await v.markSuperseded(id);
    expect((await v.load(id))!.record.supersededAt).toBe(1000);
    expect(await v.listIdentities()).toEqual([]);
    await v.beginDelete(id);
    await v.cancelDelete(id);
    expect(await v.exists(id)).toBe(true);
    expect(await v.listIdentities()).toEqual([]);
    await v.markSuperseded('ace:sha256:' + 'e'.repeat(64));
    expect(await redis.exists('acemcp:identity:ace:sha256:' + 'e'.repeat(64))).toBe(0);
  });
});
