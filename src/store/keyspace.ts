// Every Redis key this service writes. All of them assume a non-clustered Redis: scripts build
// key names from prefixes.
export const IDENTITY_PREFIX = 'acemcp:identity:';
export const TOKEN_PREFIX = 'acemcp:token:';
export const RATE_PREFIX = 'acemcp:rate:';
export const OAUTH_CODE_PREFIX = 'acemcp:oauth:code:';
export const OAUTH_PAGE_PREFIX = 'acemcp:oauth:page:';
/** Keyed by the SHA-256 of the client access / refresh token. */
export const OAUTH_ACCESS_PREFIX = 'acemcp:oauth:access:';
export const OAUTH_REFRESH_PREFIX = 'acemcp:oauth:refresh:';
/** `acemcp:oauth:grant:<id>`; the per-identity index is `acemcp:oauth:grants:<aceId>`. */
export const OAUTH_GRANT_PREFIX = 'acemcp:oauth:grant';
/** ZSET aceId → createdAt, enumerated by the receiver workers. */
export const IDENTITIES_INDEX = 'acemcp:identities';
/** Pub/sub channel of receiver notices (`stop <aceId>` / `start <aceId>`) around a settings change. */
export const RECEIVER_CHANNEL = 'acemcp:receivers';

/** Rate-limit bucket names (under RATE_PREFIX). */
export const rateBucket = {
  tool: (aceId: string) => `tool:${aceId}`,
  owner: (aceId: string) => `owner:${aceId}`,
  request: (ip: string) => `request:${ip}`,
  /** The owner API's per-IP bucket (apart from /mcp's). */
  ownerRequest: (ip: string) => `owner-request:${ip}`,
  create: (ip: string) => `create:${ip}`,
  oauthAuthorize: (ip: string) => `oauth-authorize:${ip}`,
  oauthToken: (ip: string) => `oauth-token:${ip}`,
};

/**
 * Every key that belongs to one hosted identity. IdentityVault.delete removes all of them except
 * the store locks and the owner-wait counter, which expire on their own.
 */
export function identityKeys(aceId: string) {
  return {
    /** Hash: sealed identity export, KEK id, token hash, timestamps. */
    record: IDENTITY_PREFIX + aceId,
    /** Prefix of the ACEStore values (binary, sealed): SDK state, message log, settings. */
    storeValues: `acemcp:store:${aceId}:`,
    /** Set: the exact ACEStore key list. */
    storeKeys: `acemcp:keys:${aceId}`,
    /** String: the total length of the sealed ACEStore values (the per-identity byte cap). */
    storeBytes: `acemcp:bytes:${aceId}`,
    /** Prefix of the ACEStore locks. */
    locks: `acemcp:lock:${aceId}:`,
    /** Counter (with a TTL) of owner-API settings changes waiting for the settings lock: tool calls stand aside. */
    ownerWaiting: `acemcp:owner-waiting:${aceId}`,
    /** The per-identity tool-call and owner-API rate buckets. */
    toolRate: RATE_PREFIX + rateBucket.tool(aceId),
    ownerRate: RATE_PREFIX + rateBucket.owner(aceId),
    /** ZSET: the identity's OAuth client grant ids. */
    grants: `${OAUTH_GRANT_PREFIX}s:${aceId}`,
  };
}
