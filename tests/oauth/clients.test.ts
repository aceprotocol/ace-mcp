import { describe, expect, it, vi } from 'vitest';
import type { Redis } from 'ioredis';
import { fetchClientMetadata, isAllowedRedirectUri, redirectUriMatches } from '../../src/oauth/clients.js';
import { OAuthStore } from '../../src/oauth/store.js';

// The outbound policy itself (DNS pinning, private answers, redirects, size and time bounds) is the SDK's
// publicHttpsFetch and is tested there; this covers what CIMD adds on top.
const id = 'https://client.example/oauth/client.json';
const metadata = { client_id: id, client_name: 'Client', token_endpoint_auth_method: 'none', redirect_uris: ['https://client.example/cb'] };
const serve = (body: string, status = 200, contentType = 'application/json') =>
  vi.fn<typeof fetch>(async () => new Response(body, { status, headers: { 'content-type': contentType } }));

describe('CIMD client metadata', () => {
  it('fetches the client id URL as JSON and keeps the validated fields', async () => {
    const fetch = serve(JSON.stringify(metadata));
    expect(await fetchClientMetadata(id, fetch)).toEqual({ clientId: id, clientName: 'Client', redirectUris: metadata.redirect_uris });
    expect(fetch).toHaveBeenCalledWith(id, { headers: { accept: 'application/json' } });
  });
  it.each(['http://client.example/client.json', 'https://user:secret@client.example/client.json', id + '#fragment', 'file:///etc/passwd'])('rejects an unsafe client id %s without fetching', async (url) => {
    const fetch = serve(JSON.stringify(metadata));
    expect(await fetchClientMetadata(url, fetch)).toBeNull(); expect(fetch).not.toHaveBeenCalled();
  });
  it('refuses redirects, incorrect media type, fetch failures and mismatching metadata', async () => {
    for (const [body, status, type] of [[JSON.stringify(metadata), 302, 'application/json'], [JSON.stringify(metadata), 200, 'text/html'], ['{', 200, 'application/json'], [JSON.stringify({ ...metadata, client_id: 'https://other.example/client.json' }), 200, 'application/json'], [JSON.stringify({ ...metadata, redirect_uris: ['javascript:alert(1)'] }), 200, 'application/json'], [JSON.stringify({ ...metadata, token_endpoint_auth_method: 'client_secret_basic' }), 200, 'application/json']] as const) {
      expect(await fetchClientMetadata(id, serve(body, status, type))).toBeNull();
    }
    expect(await fetchClientMetadata(id, async () => { throw new Error('blocked'); })).toBeNull();
  });
  it('uses exact HTTPS redirects and only permits ephemeral ports for loopback', () => {
    expect(redirectUriMatches('https://client.example/cb', 'https://client.example/cb/')).toBe(false);
    expect(redirectUriMatches('http://127.0.0.1/cb', 'http://127.0.0.1:51999/cb')).toBe(true);
    expect(redirectUriMatches('http://localhost/cb', 'http://localhost.evil.example/cb')).toBe(false);
    for (const bad of ['http://client.example/cb', 'https://client.example/cb#x', 'https://u:p@client.example/cb']) expect(isAllowedRedirectUri(bad)).toBe(false);
  });
  it('caches client metadata by URL for the page TTL, so a consent round trip fetches once', async () => {
    const fetch = serve(JSON.stringify(metadata));
    let now = 1000;
    const store = new OAuthStore({} as Redis, { fetch, clock: () => now });
    expect(await store.getClient(id)).toMatchObject({ clientId: id });
    expect(await store.getClient(id)).toMatchObject({ clientId: id });
    expect(fetch).toHaveBeenCalledTimes(1);
    now += 301;
    await store.getClient(id);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it('caches a failed metadata fetch for 30 s only', async () => {
    const fetch = serve('{', 200);
    let now = 1000;
    const store = new OAuthStore({} as Redis, { fetch, clock: () => now });
    expect(await store.getClient(id)).toBeNull();
    now += 29;
    expect(await store.getClient(id)).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(1);
    now += 2;
    await store.getClient(id);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
