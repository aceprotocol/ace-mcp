import { publicHttpsFetch } from '@ace-protocol/sdk';
import type { OAuthClient } from './store.js';

const MAX_REDIRECT_URIS = 10;
const MAX_URI_LENGTH = 2048;
/** Total bytes of all redirect URIs in one registration. */
const MAX_REDIRECT_URI_BYTES = 4096;
const MAX_CLIENT_NAME = 128;
/**
 * A URL hostname that names this machine: `localhost`, `*.localhost` (RFC 6761 § 6.3), 127.0.0.0/8 or `[::1]` (URL
 * hostnames keep IPv6 brackets). For Host/Origin checks, which ALLOWED_HOSTS already gates.
 */
export function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '[::1]' || /^127(\.\d{1,3}){3}$/.test(hostname);
}
/** Plain-http redirect hosts (RFC 8252 § 7.3): the open-redirect gate takes only these exact names. */
const REDIRECT_LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['127.0.0.1', 'localhost', '[::1]']);

/**
 * A redirect URI this server will ever send a code to: `https://` with a host, or plain-http
 * loopback (REDIRECT_LOOPBACK_HOSTS, any port); no userinfo, no fragment, printable ASCII only.
 * Codes are later appended to the exact registered string, so this check is the open-redirect gate.
 */
export function isAllowedRedirectUri(v: unknown): v is string {
  if (typeof v !== 'string' || v.length > MAX_URI_LENGTH || !/^[\x21-\x7e]+$/.test(v) || v.includes('#')) return false;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return false;
  }
  if (u.username || u.password) return false;
  if (u.protocol === 'https:') return u.hostname !== '';
  if (u.protocol === 'http:') return REDIRECT_LOOPBACK_HOSTS.has(u.hostname);
  return false;
}

/**
 * Whether an authorization request's `redirect_uri` matches one registered URI. Exact string match,
 * except that a plain-http loopback URI matches whatever port the request names (RFC 8252 § 7.3:
 * native apps pick an ephemeral port at run time) — same host, path and query. https URIs are exact.
 */
export function redirectUriMatches(registered: string, requested: string): boolean {
  if (registered === requested) return true;
  if (!isAllowedRedirectUri(requested)) return false;
  let r: URL;
  let q: URL;
  try {
    r = new URL(registered);
    q = new URL(requested);
  } catch {
    return false;
  }
  return r.protocol === 'http:' && q.protocol === 'http:' && REDIRECT_LOOPBACK_HOSTS.has(r.hostname) && r.hostname === q.hostname
    && r.pathname === q.pathname && r.search === q.search;
}

const CIMD_FETCH = publicHttpsFetch({ timeoutMs: 5000, maxResponseBytes: 32_768 });

/** CIMD retrieval through the SDK policy for untrusted URLs: HTTPS, DNS pinning, no private addresses, no redirects, bounded body. */
export async function fetchClientMetadata(clientId: string, fetch: typeof globalThis.fetch = CIMD_FETCH): Promise<OAuthClient | null> {
  let u: URL;
  try { u = new URL(clientId); } catch { return null; }
  if (u.protocol !== 'https:' || u.username || u.password || u.hash || clientId.length > MAX_URI_LENGTH) return null;
  try {
    const res = await fetch(clientId, { headers: { accept: 'application/json' } });
    if (res.status !== 200 || !res.headers.get('content-type')?.split(';')[0]?.trim().endsWith('/json')) return null;
    const m = JSON.parse(await res.text()) as Record<string, unknown>;
    if (m.client_id !== clientId || !Array.isArray(m.redirect_uris) || !m.redirect_uris.length || m.redirect_uris.length > MAX_REDIRECT_URIS
      || !m.redirect_uris.every(isAllowedRedirectUri) || m.redirect_uris.join('').length > MAX_REDIRECT_URI_BYTES
      || m.token_endpoint_auth_method !== 'none' || m.client_name !== undefined && (typeof m.client_name !== 'string' || m.client_name.length > MAX_CLIENT_NAME)) return null;
    return { clientId, redirectUris: m.redirect_uris, ...(typeof m.client_name === 'string' ? { clientName: m.client_name } : {}) };
  } catch { return null; }
}
