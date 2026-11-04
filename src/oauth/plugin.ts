import type { FastifyInstance } from 'fastify';
import type { Redis } from 'ioredis';
import type { ToolDeps } from '../mcp/tools/shared.js';
import { registerAuthorizeRoutes } from './authorize.js';
import { registerMetadataRoutes } from './metadata.js';
import { OAuthStore } from './store.js';
import { registerTokenRoute } from './token.js';

/** Small bodies only: authorization form posts. */
export const OAUTH_BODY_LIMIT = 16 * 1024;

/**
 * The OAuth 2.1 routes as an encapsulated Fastify plugin (registered WITHOUT fastify-plugin): the
 * JSON and form parsers added here exist only in this context, so `/mcp` keeps reading the raw
 * stream through the root's catch-all parser. Root onRequest hooks (Host/Origin guard) still apply.
 */
export async function oauthPlugin(app: FastifyInstance, opts: { deps: ToolDeps; redis: Redis }): Promise<void> {
  const { deps } = opts;
  const store = new OAuthStore(opts.redis);

  // Nothing here may be cached: codes, nonces, consent pages.
  app.addHook('onRequest', async (_req, reply) => {
    reply.header('cache-control', 'no-store').header('pragma', 'no-cache');
  });

  app.removeAllContentTypeParsers();
  // Fastify's own JSON parser (rejects __proto__ / constructor.prototype keys).
  app.addContentTypeParser('application/json', { parseAs: 'string', bodyLimit: OAUTH_BODY_LIMIT }, app.getDefaultJsonParser('error', 'error'));
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string', bodyLimit: OAUTH_BODY_LIMIT }, (_req, body, done) => {
    done(null, new URLSearchParams(body as string));
  });

  // Parser / body-limit / unsupported-media-type errors: RFC 6749 JSON shape, never a stack or detail.
  app.setErrorHandler((err: { statusCode?: number }, req, reply) => {
    // 415 (unsupported media type) is a malformed request in RFC 6749 terms: 400 invalid_request.
    const raw = typeof err.statusCode === 'number' && err.statusCode >= 400 && err.statusCode < 500 ? err.statusCode : 500;
    const status = raw === 415 ? 400 : raw;
    if (status === 500) deps.logger.error({ err, route: req.routeOptions.url }, 'oauth route failed');
    return reply.code(status)
      .send(status === 500 ? { error: 'server_error' } : { error: 'invalid_request', error_description: 'malformed request' });
  });

  registerMetadataRoutes(app);
  registerAuthorizeRoutes(app, { ...deps, store });
  registerTokenRoute(app, { store, grants: deps.grants, vault: deps.vault, logger: deps.logger, rateLimiter: deps.rateLimiter, tokenRateLimit: deps.config.toolRateLimit });
}
