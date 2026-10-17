import type { Redis } from 'ioredis';
import { SoftwareIdentity, sha256Hex } from '@ace-protocol/sdk';
import { IDENTITIES_INDEX, IDENTITY_PREFIX, OAUTH_GRANT_PREFIX, TOKEN_PREFIX, identityKeys } from '../store/keyspace.js';
import { generateToken, isTokenShape } from './token.js';
import { checkExec, luaScript, runScript } from '../store/scripts.js';
import { nowSeconds } from '../clock.js';
import { SealedDataError, deriveSubkey, kekCipher, kekId, locateSealed } from './kek.js';

export interface IdentityRecord {
  aceId: string;
  createdAt: number;
  lastUsedAt: number;
  exportedAt?: number;
  /** The relay holds a newer key event log (the identity was imported and re-keyed elsewhere): no receiver runs. */
  supersededAt?: number;
}

/** The identity does not exist (never did, or was deleted while the call ran). */
export class IdentityNotFoundError extends Error {
  constructor() {
    super('identity not found');
    this.name = 'IdentityNotFoundError';
  }
}

// Atomic token rotation: only for an existing identity; new token key in, old token key out.
// KEYS[1] identity hash, ARGV[1] token prefix, ARGV[2] new hash, ARGV[3] aceId.
const ROTATE = luaScript('rotate', 1, `
local old = redis.call('HGET', KEYS[1], 'tokenHash')
if not old then return 0 end
redis.call('HSET', KEYS[1], 'tokenHash', ARGV[2])
redis.call('SET', ARGV[1] .. ARGV[2], ARGV[3])
redis.call('DEL', ARGV[1] .. old)
return 1`);

// Set one field only if the identity exists (no stub records). KEYS[1] identity hash.
const HSET_IF_EXISTS = luaScript('hset_if_exists', 1, `
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
return 1`);

// Delete everything of one identity in one step, so there is never a half-deleted identity: token,
// ACEStore values, key set and byte count, client grants, rate buckets, record, index entry.
// KEYS: record, identities index, store key set, tool rate, owner rate, grants index, store byte count.
// ARGV: aceId, token prefix, store value prefix, grant prefix.
const DESTROY = luaScript('identity_destroy', 7, `
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
local tok = redis.call('HGET', KEYS[1], 'tokenHash')
if tok then redis.call('DEL', ARGV[2] .. tok) end
for _, k in ipairs(redis.call('SMEMBERS', KEYS[3])) do redis.call('DEL', ARGV[3] .. k) end
for _, g in ipairs(redis.call('ZRANGE', KEYS[6], 0, -1)) do redis.call('DEL', ARGV[4] .. g) end
redis.call('DEL', KEYS[1], KEYS[3], KEYS[4], KEYS[5], KEYS[6], KEYS[7])
redis.call('ZREM', KEYS[2], ARGV[1])
return 1`);

// Deletion marker: once set, the identity is gone to every reader (load, exists, token and OAuth auth, the
// receiver workers) and its store refuses writes, in every process, so no client can persist a relay registration
// timestamp (the SDK RelayClient does so before each register) and none registers it again. It leaves the enumeration
// index so no worker scan restarts its receiver. DESTROY removes it with the record; CANCEL_DELETE resumes the
// identity (back in the index unless it was superseded).
// KEYS[1] identity hash, KEYS[2] identities index; ARGV[1] aceId.
const BEGIN_DELETE = luaScript('identity_begin_delete', 2, `
if redis.call('EXISTS', KEYS[1]) == 0 or redis.call('HEXISTS', KEYS[1], 'deleting') == 1 then return 0 end
redis.call('HSET', KEYS[1], 'deleting', '1')
redis.call('ZREM', KEYS[2], ARGV[1])
return 1`);
const CANCEL_DELETE = luaScript('identity_cancel_delete', 2, `
if redis.call('HDEL', KEYS[1], 'deleting') == 0 then return 0 end
if redis.call('HEXISTS', KEYS[1], 'supersededAt') == 0 then
  redis.call('ZADD', KEYS[2], tonumber(redis.call('HGET', KEYS[1], 'createdAt') or '0'), ARGV[1])
end
return 1`);

// Superseded: the identity stays loadable (the owner can still export or delete it) but leaves the enumeration index,
// so no worker scan starts its receiver again. KEYS[1] identity hash, KEYS[2] identities index; ARGV[1] aceId, ARGV[2] now.
const SUPERSEDE = luaScript('identity_supersede', 2, `
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
redis.call('HSET', KEYS[1], 'supersededAt', ARGV[2])
redis.call('ZREM', KEYS[2], ARGV[1])
return 1`);

// A token resolves only to a live identity (not one being deleted). KEYS[1] token key; ARGV[1] identity prefix.
const RESOLVE_TOKEN = luaScript('resolve_token', 1, `
local id = redis.call('GET', KEYS[1])
if not id or redis.call('HEXISTS', ARGV[1] .. id, 'deleting') == 1 then return false end
return id`);

/**
 * Hosted identities. The identity export (root, next-root and signing seeds plus the KEL) is sealed with AES-256-GCM
 * under the identity's HKDF subkey of MCP_KEK (purpose `identity`, AAD `identity\0<aceId>`), next to the KEK id it
 * was sealed under. The owner token is stored only as its SHA-256.
 */
export class IdentityVault {
  readonly #redis: Redis;
  readonly #kek: Buffer;
  readonly #kid: string;
  readonly #clock: () => number;

  constructor(redis: Redis, kek: Buffer, clock: () => number = nowSeconds) {
    this.#redis = redis;
    this.#kek = Buffer.from(kek);
    this.#kid = kekId(kek);
    this.#clock = clock;
  }

  #cipher(aceId: string) { return kekCipher(deriveSubkey(this.#kek, 'identity', aceId)); }
  #aad(aceId: string) { return `identity\0${aceId}`; }

  async create(): Promise<{ identity: SoftwareIdentity; token: string; record: IdentityRecord }> {
    const identity = await SoftwareIdentity.generate();
    const aceId = identity.getACEId();
    const { token, hash } = generateToken();
    const now = this.#clock();
    const enc = this.#cipher(aceId).seal(this.#aad(aceId), JSON.stringify(identity.exportPrivateKey())).toString('base64');
    const res = await this.#redis.multi()
      .hset(IDENTITY_PREFIX + aceId, { enc, kid: this.#kid, tokenHash: hash, createdAt: String(now), lastUsedAt: String(now) })
      .set(TOKEN_PREFIX + hash, aceId)
      .zadd(IDENTITIES_INDEX, now, aceId)
      .exec();
    checkExec('identity vault create', res);
    return { identity, token, record: { aceId, createdAt: now, lastUsedAt: now } };
  }

  /** The owner token hash (OAuth grants are bound to it); null for an unknown or deleting identity. */
  async ownerHash(aceId: string): Promise<string | null> {
    const [hash, deleting] = await this.#redis.hmget(IDENTITY_PREFIX + aceId, 'tokenHash', 'deleting');
    return deleting === null ? hash : null;
  }

  async resolveToken(token: string): Promise<string | null> {
    if (!isTokenShape(token)) return null;
    return await runScript(this.#redis, RESOLVE_TOKEN, TOKEN_PREFIX + sha256Hex(token), IDENTITY_PREFIX) as string | null;
  }

  /**
   * Decrypts and re-verifies the identity (SoftwareIdentity.fromExport verifies the KEL). A blob sealed under another
   * KEK, one that does not open, or one that is not a KEL export of this aceId is a SealedDataError (`corrupt_record`).
   */
  async load(aceId: string): Promise<{ identity: SoftwareIdentity; record: IdentityRecord } | null> {
    const d = await this.#redis.hgetall(IDENTITY_PREFIX + aceId);
    if (!d.enc || d.deleting) return null;
    const identity = locateSealed(aceId, 'identity', () => {
      if (d.kid !== this.#kid) throw new SealedDataError(`identity record is sealed under another KEK (kid ${String(d.kid).slice(0, 16)})`);
      const plaintext = this.#cipher(aceId).open(this.#aad(aceId), Buffer.from(d.enc, 'base64')).toString('utf8');
      try {
        return SoftwareIdentity.fromExport(JSON.parse(plaintext) as unknown);
      } catch (e) {
        throw new SealedDataError('identity record is not a valid key event log export', { cause: e });
      }
    });
    if (identity.getACEId() !== aceId) throw new SealedDataError('identity record does not match its key', { aceId, key: 'identity' });
    const record: IdentityRecord = { aceId, createdAt: Number(d.createdAt), lastUsedAt: Number(d.lastUsedAt) };
    if (d.exportedAt) record.exportedAt = Number(d.exportedAt);
    if (d.supersededAt) record.supersededAt = Number(d.supersededAt);
    return { identity, record };
  }

  /** The identity exists and is not being deleted. */
  async exists(aceId: string): Promise<boolean> {
    const [enc, deleting] = await this.#redis.hmget(IDENTITY_PREFIX + aceId, 'enc', 'deleting');
    return enc !== null && deleting === null;
  }

  async touch(aceId: string): Promise<void> {
    await runScript(this.#redis, HSET_IF_EXISTS, IDENTITY_PREFIX + aceId, 'lastUsedAt', String(this.#clock()));
  }

  async rotateToken(aceId: string): Promise<string> {
    const { token, hash } = generateToken();
    const ok = await runScript(this.#redis, ROTATE, IDENTITY_PREFIX + aceId, TOKEN_PREFIX, hash, aceId);
    if (ok !== 1) throw new IdentityNotFoundError();
    return token;
  }

  async markExported(aceId: string): Promise<void> {
    const ok = await runScript(this.#redis, HSET_IF_EXISTS, IDENTITY_PREFIX + aceId, 'exportedAt', String(this.#clock()));
    if (ok !== 1) throw new IdentityNotFoundError();
  }

  /** Mark the identity superseded (see IdentityRecord.supersededAt); a no-op for an unknown identity. */
  async markSuperseded(aceId: string): Promise<void> {
    await runScript(this.#redis, SUPERSEDE, IDENTITY_PREFIX + aceId, IDENTITIES_INDEX, aceId, String(this.#clock()));
  }

  /**
   * Mark the identity as being deleted (durable, cross-process): from now on it is gone to load / exists / token and
   * OAuth auth / listIdentities and its store refuses writes (so it cannot register at the relay again). Throws
   * IdentityNotFoundError for an unknown identity or one already being deleted.
   */
  async beginDelete(aceId: string): Promise<void> {
    if (await runScript(this.#redis, BEGIN_DELETE, IDENTITY_PREFIX + aceId, IDENTITIES_INDEX, aceId) !== 1) throw new IdentityNotFoundError();
  }

  /** Undo beginDelete when the deletion did not happen. */
  async cancelDelete(aceId: string): Promise<void> {
    await runScript(this.#redis, CANCEL_DELETE, IDENTITY_PREFIX + aceId, IDENTITIES_INDEX, aceId);
  }

  /** Delete the identity and everything stored for it (and the deletion marker), atomically. A no-op for an unknown identity. */
  async delete(aceId: string): Promise<void> {
    const k = identityKeys(aceId);
    await runScript(this.#redis, DESTROY, k.record, IDENTITIES_INDEX, k.storeKeys, k.toolRate, k.ownerRate, k.grants, k.storeBytes, aceId, TOKEN_PREFIX, k.storeValues, OAUTH_GRANT_PREFIX + ':');
  }

  /** One page of hosted aceIds (oldest first), for the receiver workers. */
  async listIdentities(offset = 0, limit = 1000): Promise<string[]> {
    return this.#redis.zrange(IDENTITIES_INDEX, offset, offset + limit - 1);
  }
}
