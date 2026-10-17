import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import type { McpConfig } from './config.js';
import { IdentityVault } from './identity/vault.js';
import { AgentRuntime } from './agent/runtime.js';
import { RateLimiter } from './store/rate-limit.js';
import { GrantStore } from './oauth/grants.js';
import { ownerPlugin } from './owner.js';
import { authContext, bearerToken, type AuthContext } from './mcp/auth-context.js';
import { BODY_LIMIT, createEndpoint } from './mcp/server.js';
import { consoleLogger, type ToolDeps } from './mcp/tools/shared.js';
import { Telemetry } from './telemetry.js';
import { oauthPlugin } from './oauth/plugin.js';
import { baseUrl, resourceUrl } from './oauth/metadata.js';
import { rateBucket } from './store/keyspace.js';

export interface McpApp { app: FastifyInstance; grants: GrantStore; vault: IdentityVault; runtime: AgentRuntime; telemetry: Telemetry; deps: ToolDeps }

const HEALTH_TIMEOUT_MS = 2000;

/** Redis answers PING within `ms`, or this rejects. */
async function pingWithin(redis: Redis, ms: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([redis.ping(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('ping timed out')), ms); })]);
  } finally {
    clearTimeout(timer);
  }
}

/** A JSON-RPC error response for a request that never reaches the MCP transport. */
function rpcError(reply: FastifyReply, status: number, code: number, message: string): FastifyReply {
  return reply.code(status).send({ jsonrpc: '2.0', error: { code, message }, id: null });
}

/** Lower-cased hostname of a Host header (port stripped, IPv6 brackets kept), or null if unparsable. */
function hostnameOf(host: string | undefined): string | null {
  if (!host) return null;
  try {
    const u = new URL(`http://${host}`);
    return u.username || u.password || u.pathname !== '/' ? null : u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** `localhost`, `*.localhost`, 127.0.0.0/8 or [::1] (URL hostnames keep IPv6 brackets). */
export function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '[::1]' || /^127(\.\d{1,3}){3}$/.test(hostname);
}

/**
 * The full origin must be one of ours: host in ALLOWED_HOSTS and scheme `https` on its default
 * port (the URL parser drops an explicit `:443`, so the port must be empty). A loopback host is
 * development: `http` or `https` on any port. No Origin header (non-browser clients) passes; the
 * opaque `null` origin and anything unparsable do not.
 */
export function originAllowed(origin: string | undefined, allowedHosts: string[]): boolean {
  if (origin === undefined) return true;
  let u: URL;
  try {
    u = new URL(origin);
  } catch {
    return false; // includes the opaque "null" origin
  }
  const host = u.hostname.toLowerCase();
  if (!allowedHosts.includes(host)) return false;
  if (u.username || u.password || u.pathname !== '/' || u.search || u.hash) return false; // not an origin
  if (isLoopbackHost(host)) return u.protocol === 'https:' || u.protocol === 'http:';
  return u.protocol === 'https:' && u.port === '';
}

/** `relayFetch` replaces the relay transport (tests inject failures); production leaves it unset. */
export async function buildApp(opts: { config: McpConfig; redis: Redis; logger?: boolean; relayFetch?: typeof fetch }): Promise<McpApp> {
  const { config, redis } = opts;
  const app = Fastify({ logger: opts.logger ?? false, bodyLimit: BODY_LIMIT, trustProxy: config.trustProxy });
  const vault = new IdentityVault(redis, config.kek);
  const logger = opts.logger ? app.log : consoleLogger;
  const runtime = new AgentRuntime({ redis, vault, config, logger, ...(opts.relayFetch ? { fetch: opts.relayFetch } : {}) });
  const grants = new GrantStore(redis, vault);
  const rateLimiter = new RateLimiter(redis);
  const telemetry = new Telemetry();
  const deps: ToolDeps = { runtime, vault, grants, config, rateLimiter, logger, telemetry };

  // The MCP transport reads and bounds (BODY_LIMIT) the body itself: leave the raw stream unread.
  app.removeAllContentTypeParsers();
  app.addContentTypeParser('*', (_req, _payload, done) => done(null));

  // DNS-rebinding guard: runs before routing, so nothing (no session, no tool) runs for a foreign Host/Origin.
  // No CORS headers are ever set.
  app.addHook('onRequest', async (req, reply) => {
    const host = hostnameOf(req.headers.host);
    if (!host || !config.allowedHosts.includes(host)) return reply.code(403).send({ error: 'forbidden_host' });
    if (!originAllowed(req.headers.origin, config.allowedHosts)) return reply.code(403).send({ error: 'forbidden_origin' });
  });

  // Readiness: every request needs Redis, so 503 when it does not answer in time. Counts live on the metrics port.
  app.get('/health', async (_req, reply) => {
    try {
      await pingWithin(redis, HEALTH_TIMEOUT_MS);
    } catch {
      return reply.code(503).send({ ok: false, error: 'redis_unavailable' });
    }
    return { ok: true };
  });

  // OAuth 2.1 auto-provisioning (spec § 5.8). Encapsulated: its JSON/form parsers do not reach /mcp.
  await app.register(oauthPlugin, { deps, redis });

  await app.register(ownerPlugin, { deps });
  const endpoint = createEndpoint(deps);
  const handle = async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const token = bearerToken(req.headers.authorization);
    // The per-IP limit counts every request and is checked first: an unauthenticated flood gets 429 (not 401) and
    // costs no token lookup.
    const hit = await rateLimiter.hit(rateBucket.request(req.ip), config.toolRateLimit, 60);
    if (!hit.allowed) { reply.header('retry-after', String(hit.retryAfter)); return rpcError(reply, 429, -32000, 'Rate limit exceeded'); }
    const grant = token ? await grants.resolve(token, resourceUrl(req)) : null;
    if (!grant) {
      reply.header('www-authenticate', `Bearer resource_metadata="${baseUrl(req)}/.well-known/oauth-protected-resource/mcp", error="invalid_token"`);
      return rpcError(reply, 401, -32001, 'A valid client access token is required on every request.');
    }
    const auth: AuthContext = { bearerAceId: grant.aceId, scopes: grant.scopes, ip: req.ip };
    reply.hijack();
    try {
      await authContext.run(auth, () => endpoint.handle(req.raw, reply.raw));
    } catch (err) {
      req.log.error({ err }, 'MCP transport failed');
      if (!reply.raw.headersSent) reply.raw.writeHead(500, { 'content-type': 'application/json' });
      if (!reply.raw.writableEnded) reply.raw.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null }));
    }
  };
  app.post('/mcp', handle);
  app.addHook('onClose', async () => endpoint.close());

  return { app, grants, vault, runtime, telemetry, deps };
}
