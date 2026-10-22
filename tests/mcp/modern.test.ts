import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import type { McpApp } from '../../src/app.js';
import { provisionIdentity } from '../../src/identity/provision.js';
import { createStack, type Stack } from '../helpers/stack.js';
import { OAuthStore } from '../../src/oauth/store.js';
import { sha256Hex } from '@ace-protocol/sdk';
let stack: Stack, service: McpApp, url: string, token: string, ownerToken: string, aceId: string;
const meta = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 'test', version: '1' } };
async function rpc(method: string, params: Record<string, unknown> = {}, auth: string | null = token, headers: Record<string, string> = {}) {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method,
    ...(params.name ? { 'Mcp-Name': String(params.name) } : {}), ...(auth === null ? {} : { authorization: auth.startsWith('Basic ') ? auth : `Bearer ${auth}` }), ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: { ...params, _meta: meta } }) });
  return { status: res.status, headers: res.headers, body: await res.json() as any };
}
beforeAll(async () => {
  stack = await createStack(24);
  service = stack.service;
  const origin = await service.app.listen({ host: '127.0.0.1', port: 0 }); url = origin + '/mcp';
  const created = await provisionIdentity(service.deps, '127.0.0.1'); ownerToken = created.token; aceId = created.identity.getACEId();
  const issued = await service.grants.create({ aceId, ownerHash: sha256Hex(ownerToken), resource: url, clientId: 'test-client', scopes: ['ace:read'] }); token = issued.access_token;
});
afterAll(async () => { await stack.close(); });
describe('modern MCP and separate owner authority', () => {
  it('discovers without initialize, emits modern result and caches privately', async () => {
    const discovered = await rpc('server/discover'); expect(discovered.status).toBe(200); expect(discovered.body.result.resultType).toBe('complete');
    const tools = await rpc('tools/list'); expect(tools.status).toBe(200); expect(tools.body.result).toMatchObject({ resultType: 'complete', cacheScope: 'private', ttlMs: 0 });
    const names = tools.body.result.tools.map((t: any) => t.name);
    expect(names).toEqual([...names].sort());
    for (const name of ['export', 'delete', 'rotate_token', 'ace_list_intents', 'ace_broadcast_intent', 'ace_wait_for_messages']) expect(names).not.toContain(name);
    const who = await rpc('tools/call', { name: 'ace_identity', arguments: {} }); expect(who.body.result.structuredContent.aceId).toBe(aceId);
  });
  it('rejects missing, malformed, owner and wrong-audience credentials independently of session headers', async () => {
    for (const auth of [null, 'Basic invalid', ownerToken, 'bad']) expect((await rpc('tools/call', { name: 'ace_identity', arguments: {} }, auth, { 'Mcp-Session-Id': 'stolen' })).status).toBe(401);
    const wrong = await service.grants.create({ aceId, ownerHash: sha256Hex(ownerToken), resource: url + '/elsewhere', clientId: 'test', scopes: ['ace:read'] });
    expect((await rpc('server/discover', {}, wrong.access_token)).status).toBe(401);
    expect((await fetch(url, { method: 'GET', headers: { authorization: `Bearer ${token}` } })).status).toBe(404);
    expect((await rpc('tools/list', {}, token, { 'Mcp-Method': 'server/discover' })).status).toBe(400);
    const old = await fetch(url, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'old', version: '1' } } }) });
    expect(old.status).toBeGreaterThanOrEqual(400);
  });
  it('enforces scopes and refuses client credentials at owner API', async () => {
    const result = await rpc('tools/call', { name: 'ace_network', arguments: { action: 'block', peer: 'ace:sha256:' + '1'.repeat(64) } });
    expect(result.body.result.structuredContent.error).toBe('insufficient_scope');
    const denied = await service.app.inject({ method: 'POST', url: '/owner', headers: { host: 'localhost', authorization: `Bearer ${token}` }, payload: { action: 'export', args: { confirm: 'EXPORT' } } });
    expect(denied.statusCode).toBe(401);
  });
  it('binds OAuth code and token to resource, returns distinct expiring client grants, rotates refresh and revokes one grant', async () => {
    const store = new OAuthStore(stack.redis);
    const client = { clientId: 'https://client.example/metadata.json', redirectUris: ['https://client.example/callback'] };
    const verifier = 'v'.repeat(43), challenge = createHash('sha256').update(verifier).digest('base64url');
    const grant = { clientId: client.clientId, redirectUri: client.redirectUris[0], challenge, aceId, ownerHash: sha256Hex(ownerToken), resource: url, scopes: ['ace:read'] };
    const exchange = async (code: string, resource: string) => service.app.inject({ method: 'POST', url: '/oauth/token', headers: { host: new URL(url).host, 'content-type': 'application/x-www-form-urlencoded' }, payload: new URLSearchParams({ grant_type: 'authorization_code', code, client_id: client.clientId, redirect_uri: grant.redirectUri, code_verifier: verifier, resource }).toString() });
    expect((await exchange(await store.issueCode(grant), 'https://wrong.example/mcp')).json().error).toBe('invalid_target');
    const first = (await exchange(await store.issueCode(grant), url)).json(), second = (await exchange(await store.issueCode(grant), url)).json();
    expect(first.expires_in).toBe(3600); expect(first.scope).toBe('ace:read'); expect(first.access_token).not.toBe(ownerToken); expect(first.access_token).not.toBe(second.access_token);
    const renewed = await service.grants.refresh(first.refresh_token, client.clientId, url); expect(renewed?.refresh_token).not.toBe(first.refresh_token);
    expect(await service.grants.refresh(first.refresh_token, client.clientId, url)).toBeNull(); // replay revokes this grant family
    expect(await service.grants.resolve(renewed!.access_token, url)).toBeNull();
    expect(await service.grants.resolve(second.access_token, url)).not.toBeNull();
    const g = await service.grants.resolve(second.access_token, url); await service.grants.revoke(aceId, g!.id);
    expect(await service.grants.resolve(second.access_token, url)).toBeNull();
    expect(await service.grants.resolve(token, url)).not.toBeNull();
  });
});
