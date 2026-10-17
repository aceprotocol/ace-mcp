import { SCOPES } from './grants.js';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { LOOPBACK_HOSTS } from './clients.js';

/**
 * Public origin of this service for one request, e.g. `https://mcp.example`.
 *
 * The host comes from the Host header only — never X-Forwarded-Host — and the app-level onRequest
 * guard has already checked its hostname against ALLOWED_HOSTS before any route runs. The scheme is
 * always `https` for a non-loopback host (OAuth 2.1 requires TLS for everything but loopback); for a
 * loopback host it is Fastify's `req.protocol`, which honours X-Forwarded-Proto only when the peer
 * is trusted by TRUST_PROXY and otherwise reflects the socket.
 */
export function baseUrl(req: FastifyRequest): string {
  const u = new URL(`http://${req.headers.host ?? ''}`);
  const proto = LOOPBACK_HOSTS.has(u.hostname) ? (req.protocol === 'https' ? 'https' : 'http') : 'https';
  return new URL(`${proto}://${u.host}`).origin;
}

/** The protected resource (`<base>/mcp`): the audience of every grant and access token. */
export const resourceUrl = (req: FastifyRequest): string => `${baseUrl(req)}/mcp`;

/** RFC 9728 (protected resource) and RFC 8414 (authorization server) metadata. */
export function registerMetadataRoutes(app: FastifyInstance): void {
  const protectedResource = async (req: FastifyRequest) => {
    const base = baseUrl(req);
    return { resource: resourceUrl(req), authorization_servers: [base], bearer_methods_supported: ['header'], scopes_supported: SCOPES };
  };
  app.get('/.well-known/oauth-protected-resource', protectedResource);
  // RFC 9728 § 3.1: the metadata URL for resource `<base>/mcp` carries the resource path as a suffix.
  app.get('/.well-known/oauth-protected-resource/mcp', protectedResource);

  app.get('/.well-known/oauth-authorization-server', async (req) => {
    const base = baseUrl(req);
    return {
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      client_id_metadata_document_supported: true,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      authorization_response_iss_parameter_supported: true, scopes_supported: SCOPES,
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
    };
  });
}
