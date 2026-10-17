import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createStack, type Stack } from '../helpers/stack.js';
import { connect, createIdentity, startListening, type HostedTestAgent, type McpTestClient } from '../helpers/client.js';
import { AGENT_TOOLS } from '@ace-protocol/sdk/tools';
import { scopeOf } from '../../src/mcp/tools/shared.js';
import { TOOLS } from '../../src/mcp/server.js';
import { sha256Hex } from '@ace-protocol/sdk';
import { DEFAULT_SCOPES } from '../../src/oauth/grants.js';

let stack: Stack, url: string, agent: HostedTestAgent, reader: McpTestClient, standard: McpTestClient;
const PEER = 'ace:sha256:' + '1'.repeat(64);

beforeAll(async () => {
  stack = await createStack(31);
  url = await startListening(stack.service);
  agent = await createIdentity(stack.service, url, 'Scoped');
  const grant = async (scopes: string[]) => connect(url, (await stack.service.grants.create({ aceId: agent.aceId, ownerHash: sha256Hex(agent.token), clientId: 'c', resource: url, scopes })).access_token);
  reader = await grant(['ace:read']);
  standard = await grant(DEFAULT_SCOPES);
});
afterAll(async () => {
  await reader?.close(); await standard?.close(); await agent?.client.close();
  await stack?.close();
});

describe('scope map (D12)', () => {
  it('serves the SDK tool table plus only the hosted-only tools; every advertised tool and action has a scope, nothing else', async () => {
    const { tools } = await reader.client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toEqual(TOOLS.map((t) => t.name));
    const hostedOnly = ['ace_configure', 'ace_delegation', 'ace_erc8004'];
    expect(names.filter((n) => !hostedOnly.includes(n))).toEqual(AGENT_TOOLS.map((t) => t.name).sort());
    for (const t of TOOLS) {
      const actions = (t.inputSchema.properties.action?.enum ?? [undefined]) as Array<string | undefined>;
      for (const action of actions) expect(scopeOf(t, action ? { action } : {}), `${t.name}.${action}`).not.toBeNull();
      expect(scopeOf(t, { action: 'bogus' }) === null || t.actions === undefined).toBe(true);
    }
    for (const owner of ['export', 'delete', 'rotate_token', 'configure']) expect(names).not.toContain(owner);
  });

  it('a read-only client reads but cannot write: ack, import, connect, send, outbox changes, configure, credentials', async () => {
    expect((await reader.call('ace_identity')).ok).toBe(true);
    expect((await reader.call('ace_inbox', {})).ok).toBe(true);
    expect((await reader.call('ace_network', { action: 'discover' })).ok).toBe(true);
    expect((await reader.call('ace_outbox', { action: 'list' })).ok).toBe(true);
    const denied: Array<[string, Record<string, unknown>]> = [
      ['ace_inbox', { action: 'ack', messages: [] }],
      ['ace_network', { action: 'import', source: {} }],
      ['ace_network', { action: 'import_invitation', invitation: {} }],
      ['ace_network', { action: 'invite', peer: PEER }],
      ['ace_network', { action: 'connect', peer: PEER }],
      ['ace_network', { action: 'accept', peer: PEER }],
      ['ace_network', { action: 'block', peer: PEER }],
      ['ace_network', { action: 'publish' }],
      ['ace_configure', { visibility: 'public' }],
      ['ace_send', { to: PEER, type: 'ace:text:1', body: { message: 'x' } }],
      ['ace_outbox', { action: 'abandon', messageId: crypto.randomUUID() }],
      ['ace_outbox', { action: 'retry' }],
      ['ace_delegation', { action: 'issue', subject: PEER }],
      ['ace_erc8004', { action: 'attach', agentRegistry: 'eip155:8453:0x0000000000000000000000000000000000000001', agentId: '1' }],
    ];
    for (const [tool, args] of denied) expect(await reader.call(tool, args), `${tool} ${JSON.stringify(args)}`).toMatchObject({ ok: false, error: 'insufficient_scope' });
  });

  it('unauthorized calls get no argument feedback; invalid calls never pull the inbox', async () => {
    expect(await reader.call('ace_send', { bogus: 1 })).toMatchObject({ ok: false, error: 'insufficient_scope' });
    const pulls = () => stack.relay.requests.filter((r) => r.path === '/v1/inbox').length;
    const before = pulls();
    expect(await agent.client.call('ace_inbox', { limit: 0 })).toMatchObject({ ok: false, error: 'invalid_argument' });
    expect(pulls()).toBe(before);
    expect((await agent.client.call('ace_inbox', {})).ok).toBe(true);
    expect(pulls()).toBeGreaterThan(before);
  });

  it('the default consent cannot change publication policy or credentials; ace:configure can', async () => {
    expect(await standard.call('ace_configure', { visibility: 'public' })).toMatchObject({ ok: false, error: 'insufficient_scope', message: 'Requires ace:configure' });
    expect(await standard.call('ace_delegation', { action: 'issue', subject: PEER })).toMatchObject({ ok: false, error: 'insufficient_scope' });
    expect((await standard.call('ace_network', { action: 'publish' })).ok).toBe(true);
    expect((await agent.client.callOk('ace_configure', { visibility: 'public', handle: 'scoped' })).visibility).toBe('public');
    expect(stack.relay.descriptors.get(agent.aceId)!.descriptor.handle).toBe('scoped');
  });

  it('admission-widening actions need ace:admission, never granted by default; narrowing ones do not', async () => {
    const configurer = await connect(url, (await stack.service.grants.create({ aceId: agent.aceId, ownerHash: sha256Hex(agent.token), clientId: 'c', resource: url, scopes: [...DEFAULT_SCOPES, 'ace:configure'] })).access_token);
    try {
      expect(DEFAULT_SCOPES).not.toContain('ace:admission');
      for (const [tool, args] of [
        ['ace_network', { action: 'accept', peer: PEER }],
        ['ace_network', { action: 'unblock', peer: PEER }],
        ['ace_network', { action: 'invite', peer: PEER }],
        ['ace_configure', { acceptProfiles: ['ace:text:1'] }],
        ['ace_delegation', { action: 'issue', subject: PEER }],
      ] as Array<[string, Record<string, unknown>]>) expect(await configurer.call(tool, args), `${tool} ${JSON.stringify(args)}`).toMatchObject({ ok: false, error: 'insufficient_scope' });
      await agent.ownerOk('configure', { visibility: 'private' });
      expect(await configurer.call('ace_configure', { visibility: 'public' })).toMatchObject({ ok: false, error: 'insufficient_scope' });
      // Narrowing and neutral changes stay available.
      expect((await configurer.call('ace_network', { action: 'block', peer: PEER })).ok).toBe(true);
      expect((await configurer.call('ace_network', { action: 'reject', peer: PEER })).ok).toBe(true);
      expect((await configurer.callOk('ace_configure', { card: { name: 'Renamed' } })).card.name).toBe('Renamed');
      // The owner may widen; so may a client the owner granted ace:admission.
      expect((await agent.ownerOk('configure', { visibility: 'public', acceptProfiles: ['ace:text:1'] })).visibility).toBe('public');
      expect((await agent.client.call('ace_network', { action: 'unblock', peer: PEER })).ok).toBe(true);
    } finally { await configurer.close(); }
  });

  it('client tokens never reach the owner API, and owner actions require their confirmations', async () => {
    const denied = await stack.service.app.inject({ method: 'POST', url: '/owner', headers: { host: 'localhost', authorization: `Bearer ${agent.accessToken}` }, payload: { action: 'export', args: { confirm: 'EXPORT' } } });
    expect(denied.statusCode).toBe(401);
    expect(await agent.owner('export', { confirm: 'yes' })).toMatchObject({ ok: false, error: 'confirmation_required' });
    expect(await agent.owner('ace_identity', {})).toMatchObject({ ok: false, error: 'invalid_action' });
    const exported = await agent.ownerOk('export', { confirm: 'EXPORT' });
    expect(exported).toMatchObject({ aceId: agent.aceId, kel: expect.any(Array), signingSeed: expect.any(String) });
    expect(exported).not.toHaveProperty('encryptionSeed');
    expect((await agent.ownerOk('grants')).grants.length).toBeGreaterThanOrEqual(3);
  });
});
