import { publicHttpsFetch } from '@ace-protocol/sdk';
import type { OAuthClient } from './store.js';

const MAX_REDIRECT_URIS = 10;
const MAX_URI_LENGTH = 2048;
/** Total bytes of all redirect URIs in one registration. */
const MAX_REDIRECT_URI_BYTES = 4096;
const MAX_CLIENT_NAME = 128;
/** Loopback hosts a native client may listen on over plain http (RFC 8252 § 7.3). */
export const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['127.0.0.1', 'localhost', '[::1]']);

/**
 * A redirect URI this server will ever send a code to: `https://` with a host, or plain-http
 * loopback (`127.0.0.1` / `localhost` / `[::1]`, any port); no userinfo, no fragment, printable ASCII only.
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
  if (u.protocol === 'http:') return LOOPBACK_HOSTS.has(u.hostname);
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
  return r.protocol === 'http:' && q.protocol === 'http:' && LOOPBACK_HOSTS.has(r.hostname) && r.hostname === q.hostname
    && r.pathname === q.pathname && r.search === q.search;
}


/** The SDK's outbound policy for untrusted URLs: DNS pinning, no private addresses, no redirects, bounded body. */
const CIMD_FETCH = publicHttpsFetch({ timeoutMs: 5000, maxResponseBytes: 32_768 });

/** CIMD retrieval: bounded HTTPS, DNS pinning, no redirects, no credentials, no private addresses. */
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
