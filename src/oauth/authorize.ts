import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { DEFAULT_SCOPES, SCOPES } from './grants.js';
import { ACEError, sha256Hex } from '@ace-protocol/sdk';
import { defaultSettings } from '../agent/settings.js';
import { RateLimitedError, type RateLimiter } from '../store/rate-limit.js';
import { rateBucket } from '../store/keyspace.js';
import { provisionIdentity, rollbackProvisioned, type ProvisionDeps } from '../identity/provision.js';
import { baseUrl, resourceUrl } from './metadata.js';
import { isS256Challenge } from './pkce.js';
import { readParams, type Params } from './params.js';
import { redirectUriMatches } from './clients.js';
import type { OAuthClient, OAuthStore } from './store.js';

const NAME_MAX = 64;
/** Upper bound (bytes) for the free-form request parameters echoed into the page and the nonce binding. */
export const MAX_PARAM_BYTES = 1024;
/** Query parameters carried from GET to the POST as hidden fields, in this order. */
const CARRIED = ['response_type', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'state', 'scope', 'resource'] as const;

const HTML_ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };

/** Escape for HTML text and double-quoted attribute values. Every echoed value goes through this. */
export function escapeHtml(s: string): string {
  return s.replace(/[&<>"'`]/g, (c) => HTML_ESCAPES[c]);
}

// No scripts, no external assets, inline CSS only; never framed (the Create button must not be clickjacked).
// No form-action: browsers apply it to the 302 that follows the POST, which goes to the client.
const CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'";

function sendHtml(reply: FastifyReply, status: number, title: string, body: string): FastifyReply {
  return reply.code(status)
    .header('content-type', 'text/html; charset=utf-8')
    .header('content-security-policy', CSP)
    .header('x-frame-options', 'DENY')
    .header('x-content-type-options', 'nosniff')
    // same-origin, not no-referrer: under no-referrer a browser sends `Origin: null` on the form
    // POST, which the Origin guard (rightly) rejects. Nothing is leaked cross-origin either way.
    .header('referrer-policy', 'same-origin')
    .send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
:root{color-scheme:light dark;--fg:#1b1b1f;--bg:#f7f7f8;--card:#fff;--muted:#5f6168;--line:#d9dae0;--accent:#2f55d4}
@media (prefers-color-scheme:dark){:root{--fg:#ececf1;--bg:#141417;--card:#1d1d22;--muted:#a0a2ab;--line:#33343c;--accent:#8aa4ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:30rem;margin:0 auto;padding:2rem 1rem}h1{font-size:1.3rem;margin:0 0 .25rem}p{margin:.25rem 0 1rem;color:var(--muted)}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1rem;margin:1rem 0}h2{font-size:1rem;margin:0 0 .5rem}
label{display:block;font-size:.85rem;color:var(--muted);margin-bottom:.25rem}input[type=text],input[type=password]{width:100%;padding:.55rem .6rem;border:1px solid var(--line);border-radius:6px;background:transparent;color:inherit;font:inherit}
button{margin-top:.75rem;padding:.55rem 1rem;border:0;border-radius:6px;background:var(--accent);color:#fff;font:inherit;cursor:pointer}
code{word-break:break-all}h2.dest{font-size:1.1rem;color:var(--fg);margin:1rem 0 .25rem}p.warn{color:var(--fg);border-left:3px solid #d4572f;padding-left:.6rem}
</style></head><body><main>${body}</main></body></html>`);
}

function errorPage(reply: FastifyReply, status: number, message: string): FastifyReply {
  return sendHtml(reply, status, 'Authorization failed', `<h1>Authorization failed</h1><p>${escapeHtml(message)}</p>`);
}

/** An already-validated redirect_uri with params appended to the exact registered string. */
function redirectUrl(redirectUri: string, params: Record<string, string | undefined>): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined) qs.set(k, v);
  const sep = !redirectUri.includes('?') ? '?' : /[?&]$/.test(redirectUri) ? '' : '&';
  return redirectUri + sep + qs.toString();
}

function redirectTo(reply: FastifyReply, redirectUri: string, params: Record<string, string | undefined>): FastifyReply {
  return reply.header('referrer-policy', 'no-referrer').redirect(redirectUrl(redirectUri, params), 302);
}

interface Validated {
  client: OAuthClient;
  redirectUri: string;
  challenge: string;
  state: string | undefined;
  carried: Params;
}

type Outcome =
  | { kind: 'fatal'; message: string }
  | { kind: 'redirect'; redirectUri: string; error: string; description: string; state: string | undefined }
  | { kind: 'ok'; v: Validated };

/**
 * Validate an authorization request (GET query or the POSTed hidden fields alike). Until client_id
 * and redirect_uri are proven (redirectUriMatches: exact, any port for loopback) nothing is redirected: the
 * user sees an error page. After that, errors go back to the client per RFC 6749 § 4.1.2.1.
 */
async function validate(req: FastifyRequest, p: Params | null, store: OAuthStore): Promise<Outcome> {
  if (!p) return { kind: 'fatal', message: 'A request parameter was repeated.' };
  const clientId = p.get('client_id');
  const client = clientId ? await store.getClient(clientId) : null;
  if (!client) return { kind: 'fatal', message: 'Unknown client_id.' };
  const redirectUri = p.get('redirect_uri');
  if (!redirectUri || !client.redirectUris.some((r) => redirectUriMatches(r, redirectUri))) return { kind: 'fatal', message: 'redirect_uri is not registered for this client.' };
  const rawState = p.get('state');
  // An oversized state is not echoed back (RFC 6749 § 4.1.2.1 only requires echoing a valid request's state).
  const state = rawState !== undefined && Buffer.byteLength(rawState) > MAX_PARAM_BYTES ? undefined : rawState;
  const fail = (error: string, description: string): Outcome => ({ kind: 'redirect', redirectUri, error, description, state });
  for (const k of ['state', 'scope', 'resource'] as const) {
    const val = p.get(k);
    if (val !== undefined && Buffer.byteLength(val) > MAX_PARAM_BYTES) return fail('invalid_request', `${k} must be at most ${MAX_PARAM_BYTES} bytes`);
  }
  if (p.get('response_type') !== 'code') return fail('unsupported_response_type', 'response_type must be "code"');
  if (p.get('code_challenge_method') !== 'S256') return fail('invalid_request', 'code_challenge_method must be "S256"');
  const challenge = p.get('code_challenge');
  if (!isS256Challenge(challenge)) return fail('invalid_request', 'an S256 code_challenge is 43 characters of base64url');
  const resource = p.get('resource');
  if (resource !== resourceUrl(req)) return fail('invalid_target', 'resource must be this server\'s /mcp URL');
  const scopes = (p.get('scope') ?? DEFAULT_SCOPES.join(' ')).split(' ').filter(Boolean);
  if (!scopes.length || scopes.some(s => !(SCOPES as readonly string[]).includes(s))) return fail('invalid_scope', 'unsupported scope');
  p.set('scope', [...new Set(scopes)].join(' '));
  const carried: Params = new Map();
  for (const k of CARRIED) {
    const v = p.get(k);
    if (v !== undefined) carried.set(k, v);
  }
  return { kind: 'ok', v: { client, redirectUri, challenge, state, carried } };
}

function hiddenFields(carried: Params): string {
  return [...carried].map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join('\n');
}

/** The consent page's nonce is bound to exactly these carried parameters. */
function binding(carried: Params): string {
  return JSON.stringify([...carried]);
}

function consentPage(reply: FastifyReply, v: Validated, nonce: string): FastifyReply {
  const host = escapeHtml(new URL(v.redirectUri).host);
  const who = v.client.clientName
    ? `The client calls itself “${escapeHtml(v.client.clientName)}” (self-reported, not verified).`
    : 'The client did not give a name.';
  const hidden = `${hiddenFields(v.carried)}\n<input type="hidden" name="form_nonce" value="${escapeHtml(nonce)}">`;
  return sendHtml(reply, 200, 'Connect to ACE', `<h1>Connect to ACE</h1>
<h2 class="dest">Authorize scoped access for <code>${host}</code></h2>
<p>${who} Requested permissions: <code>${escapeHtml(v.carried.get('scope') ?? '')}</code>. This service holds the identity keys and can read its messages. This client cannot export keys or delete the identity; only the <code>ace:configure</code> scope lets it change publication settings, and only <code>ace:admission</code> lets it accept contacts, unblock peers, issue invitations, open its contact, list it in the directory or claim its handle.</p>
<section><h2>Create a new ACE identity for this client</h2>
<form method="post" action="/oauth/authorize">
${hidden}
<input type="hidden" name="action" value="create">
<label for="name">Agent name</label>
<input type="text" id="name" name="name" required minlength="1" maxlength="${NAME_MAX}" autocomplete="off">
<button type="submit">Create</button>
</form></section>
<section><h2>Use an existing token</h2>
<form method="post" action="/oauth/authorize">
${hidden}
<input type="hidden" name="action" value="token">
<p class="warn">The owner token is used only on this page. ${host} receives separate, revocable credentials for the displayed permissions.</p>
<label for="token">Identity token (ace_mcp_…)</label>
<input type="password" id="token" name="token" required autocomplete="off">
<button type="submit">Use this identity</button>
</form></section>`);
}

export function registerAuthorizeRoutes(app: FastifyInstance, deps: ProvisionDeps & { store: OAuthStore; rateLimiter: RateLimiter }): void {
  app.get('/oauth/authorize', async (req, reply) => {
    // Every rendered page writes a (small, 300 s) nonce key: bound per IP like the public tools.
    const hit = await deps.rateLimiter.hit(rateBucket.oauthAuthorize(req.ip), deps.config.toolRateLimit, 60);
    if (!hit.allowed) {
      reply.header('retry-after', String(hit.retryAfter));
      return errorPage(reply, 429, `Too many authorization requests from this address; retry in ${hit.retryAfter}s.`);
    }
    const qs = req.url.indexOf('?');
    const o = await validate(req, readParams(new URLSearchParams(qs < 0 ? '' : req.url.slice(qs + 1))), deps.store);
    if (o.kind === 'fatal') return errorPage(reply, 400, o.message);
    if (o.kind === 'redirect') return redirectTo(reply, o.redirectUri, { error: o.error, error_description: o.description, state: o.state });
    return consentPage(reply, o.v, await deps.store.issuePageNonce(binding(o.v.carried)));
  });

  app.post('/oauth/authorize', async (req, reply) => {
    const hit = await deps.rateLimiter.hit(rateBucket.oauthAuthorize(req.ip), deps.config.toolRateLimit, 60);
    if (!hit.allowed) { reply.header('retry-after', String(hit.retryAfter)); return errorPage(reply, 429, 'Too many authorization requests.'); }
    // Defence in depth next to the Origin guard: a browser-declared cross-site submission is refused.
    if (req.headers['sec-fetch-site'] === 'cross-site') return errorPage(reply, 403, 'Cross-site form submissions are not accepted.');
    if (!(req.body instanceof URLSearchParams)) return errorPage(reply, 400, 'Expected a form submission.');
    const p = readParams(req.body);
    const o = await validate(req, p, deps.store);
    if (o.kind === 'fatal') return errorPage(reply, 400, o.message);
    if (o.kind === 'redirect') return redirectTo(reply, o.redirectUri, { error: o.error, error_description: o.description, state: o.state });
    const v = o.v;

    // Check the user's input first, so a typo does not burn the page; then consume the one-time page
    // nonce (atomic) before any side effect, so a double submit cannot create two identities.
    const action = p!.get('action');
    const name = p!.get('name') ?? '';
    const given = (p!.get('token') ?? '').trim();
    let existing: string | null = null;
    if (action === 'create') {
      if (name.trim().length === 0 || name.length > NAME_MAX) return errorPage(reply, 400, `The agent name must be 1–${NAME_MAX} characters.`);
      // The SDK's profile rules (e.g. no control characters) before the nonce is spent.
      try {
        defaultSettings(name);
      } catch (e) {
        if (e instanceof ACEError) return errorPage(reply, 400, 'The agent name is not valid (1–64 characters, no control characters).');
        throw e;
      }
    } else if (action === 'token') {
      existing = await deps.vault.resolveToken(given);
      if (!existing) return errorPage(reply, 400, 'Unknown token.');
    } else {
      return errorPage(reply, 400, 'Choose “Create” or “Use an existing token”.');
    }
    if (!(await deps.store.takePageNonce(p!.get('form_nonce'), binding(v.carried)))) {
      return errorPage(reply, 400, 'This page was already submitted or has expired. Start again from the application.');
    }

    let aceId: string;
    let token: string;
    if (existing) {
      aceId = existing;
      token = given;
    } else {
      try {
        const c = await provisionIdentity(deps, { name }, req.ip);
        aceId = c.identity.getACEId();
        token = c.token;
      } catch (e) {
        // The page nonce is spent by now: every message sends the user back to the application.
        if (e instanceof RateLimitedError) return errorPage(reply, 429, `Too many identities created from this address (${e.message}). Start again from the application later.`);
        if (!(e instanceof ACEError)) deps.logger.error({ err: e }, 'oauth identity provisioning failed');
        return errorPage(reply, 502, 'The identity could not be registered on the relay. Start again from the application.');
      }
    }

    let code: string;
    try {
      code = await deps.store.issueCode({ clientId: v.client.clientId, redirectUri: v.redirectUri, challenge: v.challenge, aceId, ownerHash: sha256Hex(token), resource: v.carried.get('resource')!, scopes: v.carried.get('scope')!.split(' ') });
    } catch (err) {
      deps.logger.error({ err }, 'oauth code could not be stored');
      // The new token was never shown to anyone: do not leave an unreachable identity behind.
      if (!existing) await rollbackProvisioned(deps, aceId, req.ip);
      return errorPage(reply, 500, 'Something went wrong. Start again from the application.');
    }
    const params = { code, state: v.state, iss: baseUrl(req) };
    if (!existing) {
      const dest = redirectUrl(v.redirectUri, params);
      return sendHtml(reply, 200, 'Save your owner credential', `<h1>Identity created</h1><p>It starts closed and unlisted: no handle, not in the directory, and strangers cannot reach it.</p><p>Save this owner credential in your password manager. It is shown once and is never sent to the client or its model. Use it for owner settings and recovery.</p><code>${escapeHtml(token)}</code><p>ACE ID: ${escapeHtml(aceId)}</p><p><a href="${escapeHtml(dest)}">Continue to the client</a></p>`);
    }
    return redirectTo(reply, v.redirectUri, params);
  });
}
