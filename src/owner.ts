import type { FastifyInstance } from 'fastify';
import { MAX_PUBLISHED_AGENT_BYTES } from '@ace-protocol/sdk';
import { authContext, bearerToken } from './mcp/auth-context.js';
import { rateBucket } from './store/keyspace.js';
import { execute, type HostedTool, type ToolDeps } from './mcp/tools/shared.js';
import { ownerActions } from './mcp/tools/owner-actions.js';
import { hostedTools } from './mcp/tools/hosted.js';

/** Owner action name → the hosted tool it runs (the ace:configure tools under their short names, and the owner actions). */
const ACTIONS = new Map<string, HostedTool>([
  ...ownerActions.map((a) => [a.name, a] as const),
  ...hostedTools.map((t) => [t.name.replace(/^ace_/, ''), t] as const),
]);

/**
 * Owner administration: a separate HTTP surface authenticated by the owner token (OAuth client tokens are refused).
 * Actions: configure, delegation, erc8004 (the hosted-only MCP tools), grants, revoke_grant, rotate_token, export,
 * delete. Limited per IP before the owner token is checked, then per identity.
 */
export async function ownerPlugin(app: FastifyInstance, opts: { deps: ToolDeps }): Promise<void> {
  const { deps } = opts;
  app.removeAllContentTypeParsers();
  app.addContentTypeParser('application/json', { parseAs: 'string', bodyLimit: MAX_PUBLISHED_AGENT_BYTES * 2 }, app.getDefaultJsonParser('error', 'error'));
  app.addHook('onRequest', async (_req, reply) => { reply.header('cache-control', 'no-store'); });
  app.post('/owner', async (req, reply) => {
    const limited = (retryAfter: number) => reply.code(429).header('retry-after', String(retryAfter)).send({ error: 'rate_limited' });
    const ip = await deps.rateLimiter.hit(rateBucket.ownerRequest(req.ip), deps.config.toolRateLimit, 60);
    if (!ip.allowed) return limited(ip.retryAfter);
    const token = bearerToken(req.headers.authorization);
    const aceId = token ? await deps.vault.resolveToken(token) : null;
    if (!aceId) return reply.code(401).send({ error: 'owner_credential_required' });
    const own = await deps.rateLimiter.hit(rateBucket.owner(aceId), deps.config.toolRateLimit, 60);
    if (!own.allowed) return limited(own.retryAfter);
    const body = req.body as { action?: unknown; args?: Record<string, unknown> } | null;
    if (!body || typeof body.action !== 'string') return reply.code(400).send({ error: 'invalid_action' });
    const args = body.args ?? {};
    if (body.action === 'grants') return { grants: await deps.grants.list(aceId) };
    if (body.action === 'revoke_grant') {
      if (typeof args.id !== 'string') return reply.code(400).send({ error: 'invalid_argument' });
      await deps.grants.revoke(aceId, args.id);
      return { ok: true };
    }
    const owner = { bearerAceId: aceId, scopes: [], owner: true, ip: req.ip };
    const action = ACTIONS.get(body.action);
    if (!action) return reply.code(400).send({ error: 'invalid_action' });
    return authContext.run(owner, () => execute(action, args, deps));
  });
}
