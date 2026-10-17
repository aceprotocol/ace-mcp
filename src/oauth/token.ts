import { resourceUrl } from './metadata.js';
import type { GrantStore } from './grants.js';
import type { FastifyInstance, FastifyReply } from 'fastify';
import { oauthError, withinLimit } from './json.js';
import { rateBucket } from '../store/keyspace.js';
import type { IdentityVault } from '../identity/vault.js';
import type { ErrorLogger } from '../errors.js';
import { verifyS256 } from './pkce.js';
import { readParams } from './params.js';
import type { OAuthStore } from './store.js';
import type { RateLimiter } from '../store/rate-limit.js';

function tokenError(reply: FastifyReply, error: string, description: string): FastifyReply {
  return oauthError(reply, 400, error, description);
}

/**
 * RFC 6749 § 4.1.3 token endpoint for public clients with PKCE (RFC 7636). Each client receives scoped, expiring credentials with refresh rotation. The code is consumed before any other check.
 */
export function registerTokenRoute(
  app: FastifyInstance,
  deps: { store: OAuthStore; grants: GrantStore; vault: IdentityVault; logger: ErrorLogger; rateLimiter: RateLimiter; tokenRateLimit: number },
): void {
  app.post('/oauth/token', async (req, reply) => {
    // Every attempt costs a code lookup (and, on success, a token check): bounded per IP like the public tools.
    if (!(await withinLimit(reply, deps.rateLimiter, { bucket: rateBucket.oauthToken(req.ip), max: deps.tokenRateLimit, windowSeconds: 60, what: 'token requests' }))) return reply;
    if (!(req.body instanceof URLSearchParams)) return tokenError(reply, 'invalid_request', 'expected application/x-www-form-urlencoded');
    const p = readParams(req.body);
    if (!p) return tokenError(reply, 'invalid_request', 'a parameter was repeated');
    const grantType = p.get('grant_type');
    if (!grantType) return tokenError(reply, 'invalid_request', 'grant_type is required');
    if (grantType === 'refresh_token') {
      if (p.get('resource') !== resourceUrl(req)) return tokenError(reply, 'invalid_target', 'resource must match this server');
      const tokens = await deps.grants.refresh(p.get('refresh_token') ?? '', p.get('client_id') ?? '', p.get('resource')!);
      return tokens ? reply.send(tokens) : tokenError(reply, 'invalid_grant', 'refresh token is invalid or was reused');
    }
    if (grantType !== 'authorization_code') return tokenError(reply, 'unsupported_grant_type', 'only authorization_code and refresh_token are supported');
    const code = p.get('code');
    if (!code) return tokenError(reply, 'invalid_request', 'code is required');

    let grant;
    try {
      grant = await deps.store.takeCode(code);
    } catch (err) {
      deps.logger.error({ err }, 'oauth code could not be opened');
      return tokenError(reply, 'invalid_grant', 'invalid authorization code');
    }
    if (!grant) return tokenError(reply, 'invalid_grant', 'invalid, expired or already used authorization code');

    const clientId = p.get('client_id');
    if (!clientId) return tokenError(reply, 'invalid_request', 'client_id is required');
    if (grant.clientId !== clientId) return tokenError(reply, 'invalid_grant', 'code was issued to another client');
    if (p.get('redirect_uri') !== grant.redirectUri) return tokenError(reply, 'invalid_grant', 'redirect_uri does not match the authorization request');
    if (!verifyS256(p.get('code_verifier') ?? '', grant.challenge)) return tokenError(reply, 'invalid_grant', 'code_verifier does not match the code_challenge');
    if (p.get('resource') !== grant.resource || grant.resource !== resourceUrl(req)) return tokenError(reply, 'invalid_target', 'resource does not match the authorized audience');
    if (await deps.vault.ownerHash(grant.aceId) !== grant.ownerHash) return tokenError(reply, 'invalid_grant', 'the identity behind this code is no longer valid');

    return reply.code(200).send(await deps.grants.create({ aceId: grant.aceId, clientId, resource: grant.resource, scopes: grant.scopes, ownerHash: grant.ownerHash }));
  });
}
