import { checkExec, luaScript, runScript } from '../store/scripts.js';
import { OAUTH_ACCESS_PREFIX, OAUTH_GRANT_PREFIX, OAUTH_REFRESH_PREFIX, identityKeys } from '../store/keyspace.js';
import { nowSeconds } from '../clock.js';
import { RateLimitedError } from '../store/rate-limit.js';
import type { Redis } from 'ioredis';
import type { IdentityVault } from '../identity/vault.js';
import { sha256Hex } from '@ace-protocol/sdk';
import { randomOpaque } from '../identity/token.js';

/**
 * OAuth scopes a client grant can carry (each tool names its `scope` or per-action `actions`). Never defaults: `ace:configure` (publication settings,
 * credentials) and `ace:admission` (anything that widens who may reach this identity: accept, unblock, invite, public
 * visibility, acceptProfiles additions, issuing a delegation). Contact notes and message bodies are remote text that
 * can steer a model, so widening admission stays with the owner unless the owner grants it explicitly.
 */
export const SCOPES = ['ace:read', 'ace:send', 'ace:connect', 'ace:configure', 'ace:admission'] as const;
export type Scope = (typeof SCOPES)[number];
export const DEFAULT_SCOPES: Scope[] = ['ace:read', 'ace:send', 'ace:connect'];
const ACCESS_TTL = 3600;
const GRANT_TTL = 30 * 86400;
export interface ClientGrant {
  id: string; aceId: string; clientId: string; resource: string; scopes: string[]; ownerHash: string; expiresAt: number;
}
const key = (id: string) => `${OAUTH_GRANT_PREFIX}:${id}`;
const indexKey = (aceId: string) => identityKeys(aceId).grants;
const accessKey = (token: string) => OAUTH_ACCESS_PREFIX + sha256Hex(token);
const refreshKey = (token: string) => OAUTH_REFRESH_PREFIX + sha256Hex(token);
const ACCESS_RE = /^ace_access_[A-Za-z0-9_-]{43}$/;
const REFRESH_RE = /^ace_refresh_[A-Za-z0-9_-]{43}$/;

/** KEYS: grant, index. ARGV: now, grant JSON, TTL, expiresAt, id. 0 when the identity already holds 100 live grants. */
const CREATE_GRANT = luaScript('oauth_create_grant', 2, `
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[1])
if redis.call('ZCARD', KEYS[2]) >= 100 then return 0 end
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
redis.call('ZADD', KEYS[2], ARGV[4], ARGV[5]); redis.call('EXPIRE', KEYS[2], ARGV[3]); return 1`);
/** KEYS: refresh token, grant. A refresh token is used once; a replay revokes the grant. */
const CONSUME_REFRESH = luaScript('oauth_consume_refresh', 2, `
if redis.call('HGET', KEYS[1], 'used') ~= '0' then redis.call('DEL', KEYS[2]); return 0 end
redis.call('HSET', KEYS[1], 'used', '1'); return 1`);
/** OAuth credentials authorize one client, resource and scope set. Owner credentials never reach MCP. */
export class GrantStore {
  constructor(private redis: Redis, private vault: IdentityVault) {}
  async valid(g: ClientGrant, resource: string): Promise<boolean> {
    return g.resource === resource && g.expiresAt > nowSeconds() && g.ownerHash === await this.vault.ownerHash(g.aceId);
  }
  async create(input: Omit<ClientGrant, 'id' | 'expiresAt'>) {
    const now = nowSeconds();
    const g: ClientGrant = { ...input, id: randomOpaque(), expiresAt: now + GRANT_TTL };
    const stored = await runScript(this.redis, CREATE_GRANT, key(g.id), indexKey(g.aceId), now, JSON.stringify(g), GRANT_TTL, g.expiresAt, g.id);
    if (stored !== 1) throw new RateLimitedError('Revoke an existing client grant before authorizing another', 60);
    return this.tokens(g);
  }
  private async tokens(g: ClientGrant) {
    const access = 'ace_access_' + randomOpaque(), refresh = 'ace_refresh_' + randomOpaque();
    const ttl = Math.max(1, g.expiresAt - nowSeconds());
    const result = await this.redis.multi().set(accessKey(access), g.id, 'EX', Math.min(ACCESS_TTL, ttl))
      .hset(refreshKey(refresh), { grant: g.id, used: '0' }).expire(refreshKey(refresh), ttl).exec();
    checkExec('oauth token store', result);
    return { access_token: access, refresh_token: refresh, token_type: 'Bearer', expires_in: Math.min(ACCESS_TTL, ttl), scope: g.scopes.join(' ') };
  }
  /** The grant `id` names, if it is still valid for `resource`. */
  async #validGrant(id: string | null, resource: string): Promise<ClientGrant | null> {
    const raw = id && await this.redis.get(key(id));
    if (!raw) return null;
    const g = JSON.parse(raw) as ClientGrant;
    return await this.valid(g, resource) ? g : null;
  }
  async resolve(token: string, resource: string): Promise<ClientGrant | null> {
    if (!ACCESS_RE.test(token)) return null;
    return this.#validGrant(await this.redis.get(accessKey(token)), resource);
  }
  async refresh(token: string, clientId: string, resource: string) {
    if (!REFRESH_RE.test(token)) return null;
    const g = await this.#validGrant(await this.redis.hget(refreshKey(token), 'grant'), resource);
    if (!g || g.clientId !== clientId) return null;
    const consumed = await runScript(this.redis, CONSUME_REFRESH, refreshKey(token), key(g.id));
    return consumed === 1 ? this.tokens(g) : null;
  }
  async list(aceId: string): Promise<Omit<ClientGrant, 'ownerHash'>[]> {
    const index = indexKey(aceId);
    await this.redis.zremrangebyscore(index, '-inf', nowSeconds());
    const ids = await this.redis.zrange(index, 0, -1);
    if (!ids.length) return [];
    const raws = await this.redis.mget(ids.map(key));
    const gone = ids.filter((_, i) => !raws[i]);
    if (gone.length) await this.redis.zrem(index, ...gone);
    return raws.filter((r): r is string => !!r).map((r) => { const { ownerHash: _, ...g } = JSON.parse(r) as ClientGrant; return g; });
  }
  async revoke(aceId: string, id: string): Promise<void> {
    const raw = await this.redis.get(key(id));
    if (raw && (JSON.parse(raw) as ClientGrant).aceId === aceId) {
      checkExec('oauth grant revoke', await this.redis.multi().del(key(id)).zrem(indexKey(aceId), id).exec());
    }
  }
}
