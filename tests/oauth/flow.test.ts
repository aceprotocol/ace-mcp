import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { McpApp } from '../../src/app.js';
import { OAuthStore } from '../../src/oauth/store.js';
import { RATE_PREFIX, OAUTH_CODE_PREFIX } from '../../src/store/keyspace.js';
import { sha256Hex } from '@ace-protocol/sdk';
import { s256Challenge } from '../../src/oauth/pkce.js';
import { createStack, type Stack } from '../helpers/stack.js';
import { startListening } from '../helpers/client.js';
let stack: Stack, app: McpApp, base: string;
const CLIENT = 'https://client.example/metadata.json', REDIRECT = 'https://client.example/cb';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
beforeAll(async () => {
  stack = await createStack(42);
  app = stack.service;
  base = (await startListening(app)).replace(/\/mcp$/, '');
  vi.spyOn(OAuthStore.prototype, 'getClient').mockImplementation(async id => id === CLIENT ? { clientId: CLIENT, redirectUris: [REDIRECT], clientName: '<Client>' } : null);
});
afterAll(async () => { vi.restoreAllMocks(); await stack?.close(); });
beforeEach(async () => { const keys = await stack.redis.keys(`${RATE_PREFIX}*`); if (keys.length) await stack.redis.del(...keys); });
const verifier = () => randomBytes(32).toString('base64url');
const fields = (v: string, extra: Record<string, string> = {}) => ({ response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, code_challenge: s256Challenge(v), code_challenge_method: 'S256', resource: `${base}/mcp`, scope: 'ace:read ace:send ace:connect', state: 'test-state', ...extra });
async function page(f: Record<string, string>) {
  const response = await fetch(`${base}/oauth/authorize?${new URLSearchParams(f)}`, { redirect: 'manual' });
  const html = await response.text();
  return { response, html, nonce: /name="form_nonce" value="([^"]+)"/.exec(html)?.[1] };
}
function post(f: Record<string, string>, headers: Record<string, string> = {}) {
  return fetch(`${base}/oauth/authorize`, { method: 'POST', headers: { ...FORM, ...headers }, body: new URLSearchParams(f).toString(), redirect: 'manual' });
}
function token(f: Record<string, string>) {
  return fetch(`${base}/oauth/token`, { method: 'POST', headers: FORM, body: new URLSearchParams(f).toString() });
}
async function authorize(owner?: string) {
  const v = verifier(), f = fields(v), p = await page(f);
  expect(p.response.status).toBe(200);
  const r = await post({ ...f, form_nonce: p.nonce!, ...(owner ? { action: 'token', token: owner } : { action: 'create', name: 'Private agent' }) });
  let destination: string;
  if (owner) { expect(r.status).toBe(302); destination = r.headers.get('location')!; }
  else {
    expect(r.status).toBe(200);
    const html = await r.text();
    owner = /<code>(ace_mcp_[A-Za-z0-9_-]+)<\/code>/.exec(html)?.[1];
    expect(owner).toBeTruthy();
    destination = /<a href="([^"]+)"/.exec(html)![1].replaceAll('&amp;', '&');
  }
  const target = new URL(destination);
  expect(target.origin + target.pathname).toBe(REDIRECT);
  expect(target.searchParams.get('iss')).toBe(base);
  expect(target.searchParams.get('state')).toBe('test-state');
  expect(target.searchParams.toString()).not.toContain(owner);
  return { owner: owner!, exchange: { grant_type: 'authorization_code', code: target.searchParams.get('code')!, code_verifier: v, client_id: CLIENT, redirect_uri: REDIRECT, resource: `${base}/mcp` } };
}
describe('CIMD and OAuth 2.1 consent', () => {
  it('publishes audience, scopes, CIMD and refresh support; removes dynamic registration', async () => {
    const resource = await (await fetch(base + '/.well-known/oauth-protected-resource/mcp')).json();
    expect(resource).toMatchObject({ resource: `${base}/mcp`, authorization_servers: [base], scopes_supported: expect.arrayContaining(['ace:read']) });
    const metadata = await (await fetch(base + '/.well-known/oauth-authorization-server')).json();
    expect(metadata).toMatchObject({ issuer: base, client_id_metadata_document_supported: true, grant_types_supported: ['authorization_code', 'refresh_token'], code_challenge_methods_supported: ['S256'] });
    expect(metadata).not.toHaveProperty('registration_endpoint');
    expect((await fetch(base + '/oauth/register', { method: 'POST', headers: FORM, body: '' })).status).toBe(404);
  });
  it('renders escaped consent, exact permissions and custodial disclosure without scripts', async () => {
    const p = await page(fields(verifier()));
    expect(p.html).toContain('&lt;Client&gt;'); expect(p.html).toContain('ace:read ace:send ace:connect');
    expect(p.html).toContain('holds the identity keys and can read its messages');
    expect(p.response.headers.get('x-frame-options')).toBe('DENY');
    expect(p.response.headers.get('cache-control')).toBe('no-store'); expect(p.html).not.toContain('<script');
  });
  it('creates a closed, unlisted identity and gives each client expiring credentials distinct from the owner', async () => {
    const { owner, exchange } = await authorize();
    const id = await app.vault.resolveToken(owner); expect(id).toBeTruthy();
    // Registered and published, but closed and unlisted: no stranger contact requests, not in the directory.
    expect(stack.relay.cards.get(id!)?.card).toMatchObject({ contact: 'closed', listed: false, card: { name: 'Private agent', tags: ['hosted'] } });
    expect(stack.relay.cards.get(id!)?.card.handle).toBeUndefined();
    expect(await (await stack.relay.fetch('https://relay.test/v1/descriptors')).json()).toEqual({ agents: [], cursor: null });
    const response = await token(exchange); expect(response.status).toBe(200);
    const credentials = await response.json() as Record<string, unknown>;
    expect(credentials).toMatchObject({ token_type: 'Bearer', expires_in: 3600, scope: 'ace:read ace:send ace:connect' });
    expect(credentials.access_token).not.toBe(owner); expect(credentials.refresh_token).toBeTruthy();
    const again = await authorize(owner), other = await (await token(again.exchange)).json() as Record<string, unknown>;
    expect(other.access_token).not.toBe(credentials.access_token);
    expect(await (await token(exchange)).json()).toMatchObject({ error: 'invalid_grant' });
  });
  it.each(['code_verifier', 'client_id', 'redirect_uri', 'resource'])('binds and consumes the code when %s is wrong', async key => {
    const { exchange } = await authorize();
    const r = await token({ ...exchange, [key]: key === 'resource' ? 'https://wrong.example/mcp' : 'wrong' });
    expect(r.status).toBe(400); expect(((await r.json()) as {error:string}).error).toBe(key === 'resource' ? 'invalid_target' : 'invalid_grant');
    expect((await token(exchange)).status).toBe(400);
  });
  it('rejects expired codes and owner credential rotation', async () => {
    const a = await authorize(); await stack.redis.del(OAUTH_CODE_PREFIX + sha256Hex(a.exchange.code));
    expect((await token(a.exchange)).status).toBe(400);
    const b = await authorize(a.owner); const id = await app.vault.resolveToken(a.owner);
    await app.vault.rotateToken(id!);
    expect((await token(b.exchange)).status).toBe(400);
  });
  it('requires a matching single-use form nonce and rejects cross-site submissions', async () => {
    const f = fields(verifier()), p = await page(f);
    const body = { ...f, action: 'create', name: 'Agent', form_nonce: p.nonce! };
    expect((await post(body, { 'sec-fetch-site': 'cross-site' })).status).toBe(403);
    expect((await post({ ...body, state: 'changed' })).status).toBe(400);
    expect((await post(body)).status).toBe(400); // mismatching binding consumes the nonce
    expect((await post({ ...body, form_nonce: '' })).status).toBe(400);
  });
  it('refuses unknown clients and redirect substitution without redirecting', async () => {
    for (const extra of [{ client_id: 'https://evil.example/client.json' }, { redirect_uri: 'https://evil.example/cb' }]) {
      const p = await page(fields(verifier(), Object.fromEntries(Object.entries(extra).filter((entry): entry is [string, string] => typeof entry[1] === 'string')))); expect(p.response.status).toBe(400); expect(p.response.headers.get('location')).toBeNull();
    }
  });
  it.each([{ resource: 'https://wrong.example/mcp' }, { scope: 'owner' }, { code_challenge_method: 'plain' }])('rejects invalid audience, scope or PKCE before consent: %j', async extra => {
    const p = await page(fields(verifier(), Object.fromEntries(Object.entries(extra).filter((entry): entry is [string, string] => typeof entry[1] === 'string')))); expect(p.response.status).toBe(302);
    expect(new URL(p.response.headers.get('location')!).searchParams.get('error')).toMatch(/^invalid_/);
  });
  it('applies Host/Origin protection to OAuth and rejects repeated parameters', async () => {
    expect((await app.app.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server', headers: { host: 'evil.example' } })).statusCode).toBe(403);
    expect((await post({ grant_type: 'authorization_code' }, { origin: 'https://evil.example' })).status).toBe(403);
    const r = await fetch(base + '/oauth/token', { method: 'POST', headers: FORM, body: 'grant_type=authorization_code&grant_type=refresh_token' });
    expect(await r.json()).toMatchObject({ error: 'invalid_request' });
  });
});
