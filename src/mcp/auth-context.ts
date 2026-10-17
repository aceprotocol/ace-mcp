import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Per-HTTP-request auth facts, resolved before the MCP transport runs and read by the tool
 * callbacks (the MCP SDK does not hand them the request). A Bearer header with an unknown or
 * revoked token never reaches the transport: it is answered with HTTP 401 (see app.ts).
 */
export interface AuthContext {
  /** The identity of a valid Bearer token ; null without one. */
  bearerAceId: string | null;
  scopes: string[];
  owner?: boolean;
  /** The end client's IP (Fastify's req.ip, which honours TRUST_PROXY). */
  ip: string;
}

export const authContext = new AsyncLocalStorage<AuthContext>();

/** The credential of an `Authorization: Bearer <token>` header, or null. */
export function bearerToken(header: string | undefined): string | null {
  return /^Bearer\s+(\S+)\s*$/i.exec(header ?? '')?.[1] ?? null;
}

export function currentAuth(): AuthContext {
  const auth = authContext.getStore();
  if (!auth) throw new Error('tool called outside an MCP request');
  return auth;
}
