import { fetchClientMetadata } from './clients.js';
import type { Redis } from 'ioredis';
import { sha256Hex } from '@ace-protocol/sdk';
import { isOpaque, randomOpaque } from '../identity/token.js';
import { OAUTH_CODE_PREFIX, OAUTH_PAGE_PREFIX } from '../store/keyspace.js';
import { checkExec, luaScript, runScript } from '../store/scripts.js';
import { nowSeconds } from '../clock.js';

/** Authorization codes live this long (RFC 6749 § 4.1.2 recommends ≤ 10 min). */
export const CODE_TTL_SECONDS = 300;
/** A rendered consent page can be submitted once, within this window. */
export const PAGE_TTL_SECONDS = 300;
/** Client metadata documents cached per process (by URL): usable ones for PAGE_TTL_SECONDS, failures this long. */
const FAILED_CLIENT_TTL_SECONDS = 30;
const MAX_CACHED_CLIENTS = 1000;

export interface OAuthClient {
  clientId: string;
  redirectUris: string[];
  clientName?: string;
}

export interface CodeGrant {
  clientId: string;
  redirectUri: string;
  challenge: string;
  aceId: string;
  resource: string;
  scopes: string[];
  ownerHash: string;
}

// Atomic read-and-delete of a code hash: a code is consumed before anything about it is checked,
// so a second exchange always fails even when the first one failed validation. KEYS[1] code key.
const TAKE = luaScript('oauth_take', 1, `
local v = redis.call('HGETALL', KEYS[1])
if #v > 0 then redis.call('DEL', KEYS[1]) end
return v`);

export class OAuthStore {
  /** clientId → its metadata (or null: unusable) and when to fetch it again; insertion order is age. */
  readonly #clients = new Map<string, { client: OAuthClient | null; until: number }>();
  readonly #fetch?: typeof fetch;
  readonly #clock: () => number;

  constructor(private redis: Redis, opts: { fetch?: typeof fetch; clock?: () => number } = {}) {
    this.#fetch = opts.fetch;
    this.#clock = opts.clock ?? nowSeconds;
  }

  /**
   * The CIMD client metadata, fetched at most once per URL per PAGE_TTL_SECONDS (a failed fetch: per 30 s): a consent
   * round trip (GET page, POST form) and repeated authorization attempts reuse it instead of fetching the client's URL
   * on every request.
   */
  async getClient(clientId: string): Promise<OAuthClient | null> {
    const now = this.#clock();
    const hit = this.#clients.get(clientId);
    if (hit && hit.until > now) return hit.client;
    const client = await fetchClientMetadata(clientId, this.#fetch);
    this.#clients.delete(clientId);
    if (this.#clients.size >= MAX_CACHED_CLIENTS) this.#clients.delete(this.#clients.keys().next().value!);
    this.#clients.set(clientId, { client, until: now + (client ? PAGE_TTL_SECONDS : FAILED_CLIENT_TTL_SECONDS) });
    return client;
  }

  /** Mint a single-use code; only sha256(code) is stored; owner credentials are never stored with codes. Returns the code. */
  async issueCode(g: CodeGrant): Promise<string> {
    const code = randomOpaque();
    const hash = sha256Hex(code);
    const res = await this.redis.multi()
      .hset(OAUTH_CODE_PREFIX + hash, {
        clientId: g.clientId, redirectUri: g.redirectUri, challenge: g.challenge, aceId: g.aceId,
        resource: g.resource, scopes: JSON.stringify(g.scopes), ownerHash: g.ownerHash,
      })
      .expire(OAUTH_CODE_PREFIX + hash, CODE_TTL_SECONDS)
      .exec();
    checkExec('oauth code store', res);
    return code;
  }

  /**
   * A one-time nonce for a rendered consent page, bound to `binding` (the authorization request).
   * Only sha256(binding) is stored: a fixed 64-byte value per page, whatever the request carried.
   */
  async issuePageNonce(binding: string): Promise<string> {
    const nonce = randomOpaque();
    await this.redis.set(OAUTH_PAGE_PREFIX + sha256Hex(nonce), sha256Hex(binding), 'EX', PAGE_TTL_SECONDS);
    return nonce;
  }

  /** Consume a page nonce (atomic GETDEL); true only if it existed and was bound to `binding`. */
  async takePageNonce(nonce: string | undefined, binding: string): Promise<boolean> {
    if (!isOpaque(nonce)) return false;
    return (await this.redis.getdel(OAUTH_PAGE_PREFIX + sha256Hex(nonce))) === sha256Hex(binding);
  }

  /** Consume a code (atomic read + delete). null if unknown, expired or already used. */
  async takeCode(code: string): Promise<CodeGrant | null> {
    if (!isOpaque(code)) return null;
    const hash = sha256Hex(code);
    const flat = (await runScript(this.redis, TAKE, OAUTH_CODE_PREFIX + hash)) as string[];
    if (flat.length === 0) return null;
    const d: Record<string, string> = {};
    for (let i = 0; i + 1 < flat.length; i += 2) d[flat[i]] = flat[i + 1];
    return {
      clientId: d.clientId, redirectUri: d.redirectUri, challenge: d.challenge, aceId: d.aceId,
      resource: d.resource, scopes: JSON.parse(d.scopes) as string[], ownerHash: d.ownerHash,
    };
  }
}
