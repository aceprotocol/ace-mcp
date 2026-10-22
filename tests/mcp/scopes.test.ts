import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createStack, type Stack } from '../helpers/stack.js';
import { connect, createIdentity, startListening, type HostedTestAgent, type McpTestClient } from '../helpers/client.js';
import { AGENT_TOOLS } from '@ace-protocol/sdk/tools';
import { scopeOf } from '../../src/mcp/tools/shared.js';
import { TOOLS } from '../../src/mcp/server.js';
import { ACEError, sha256Hex } from '@ace-protocol/sdk';
import { DEFAULT_SCOPES } from '../../src/oauth/grants.js';
import { loadSettings, saveSettings } from '../../src/agent/settings.js';

let stack: Stack, url: string, agent: HostedTestAgent, reader: McpTestClient, standard: McpTestClient;
const PEER = 'ace:sha256:' + '1'.repeat(64);

beforeAll(async () => {
  stack = await createStack(31);
  url = await startListening(stack.service);
  agent = await createIdentity(stack.service, url);
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
      ['ace_configure', { contact: 'open' }],
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
    expect(await standard.call('ace_configure', { contact: 'open' })).toMatchObject({ ok: false, error: 'insufficient_scope', message: 'Requires ace:configure' });
    expect(await standard.call('ace_delegation', { action: 'issue', subject: PEER })).toMatchObject({ ok: false, error: 'insufficient_scope' });
    expect((await standard.call('ace_network', { action: 'publish' })).ok).toBe(true);
    expect(await agent.client.callOk('ace_configure', { contact: 'open', listed: true, handle: 'scoped' })).toMatchObject({ contact: 'open', listed: true, handle: 'scoped' });
    expect(stack.relay.cards.get(agent.aceId)!.card).toMatchObject({ handle: 'scoped', contact: 'open', listed: true });
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
      await agent.ownerOk('configure', { contact: 'closed', listed: false });
      // Opening contact, listing in the directory and claiming a handle each widen who may reach the identity.
      for (const args of [{ contact: 'open' }, { listed: true }]) {
        expect(await configurer.call('ace_configure', args), JSON.stringify(args)).toMatchObject({ ok: false, error: 'insufficient_scope' });
      }
      // Re-sending the current handle claims nothing.
      expect((await configurer.callOk('ace_configure', { handle: 'scoped', contact: 'closed', listed: false })).handle).toBe('scoped');
      // Narrowing and neutral changes stay available.
      expect((await configurer.call('ace_network', { action: 'block', peer: PEER })).ok).toBe(true);
      expect((await configurer.call('ace_network', { action: 'reject', peer: PEER })).ok).toBe(true);
      expect((await configurer.callOk('ace_configure', { card: { description: 'Renamed' } })).card.description).toBe('Renamed');
      // The owner may widen; so may a client the owner granted ace:admission.
      expect((await agent.ownerOk('configure', { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] })).contact).toBe('open');
      expect((await agent.client.call('ace_network', { action: 'unblock', peer: PEER })).ok).toBe(true);
    } finally { await configurer.close(); }
  });

  it('claiming a handle widens admission; a handle is set once; a taken handle is refused', async () => {
    const fresh = await createIdentity(stack.service, url);
    const other = await createIdentity(stack.service, url);
    const configurer = await connect(url, (await stack.service.grants.create({ aceId: fresh.aceId, ownerHash: sha256Hex(fresh.token), clientId: 'c', resource: url, scopes: [...DEFAULT_SCOPES, 'ace:configure'] })).access_token);
    const saved = (a: HostedTestAgent) => stack.service.runtime.withIdentity(a.aceId, undefined, (c) => loadSettings(c.store));
    try {
      expect(await configurer.call('ace_configure', { handle: 'fresh' })).toMatchObject({ ok: false, error: 'insufficient_scope' });
      expect(await fresh.ownerOk('configure', { handle: 'fresh' })).toMatchObject({ handle: 'fresh', address: '@fresh@relay.test', contact: 'closed', listed: false });
      expect((await saved(fresh))?.handle).toBe('fresh');
      // Set once: never changed or removed at its home; the relay refuses and the tool explains.
      for (const handle of ['renamed', '']) {
        const r = await fresh.owner('configure', { handle });
        expect(r, handle).toMatchObject({ ok: false, error: 'invalid_argument' });
        expect((r as { message: string }).message).toMatch(/set once/);
      }
      expect(stack.relay.cards.get(fresh.aceId)!.card.handle).toBe('fresh');
      expect((await configurer.callOk('ace_configure', { card: { description: 'Fresh 2' } })).handle).toBe('fresh'); // omitted: kept
      // Another identity's claim of it: handle_taken, explained, and nothing saved.
      const taken = await other.owner('configure', { handle: 'fresh' });
      expect(taken).toMatchObject({ ok: false, error: 'handle_taken' });
      expect((taken as { message: string }).message).toContain('@fresh@relay.test');
      expect((await saved(other))?.handle).toBeUndefined();
      // Settings that lost the handle (written before card records): the relay's set-once refusal comes back explained.
      await stack.service.runtime.withIdentity(fresh.aceId, undefined, async (c) => {
        const { handle: _h, ...rest } = (await loadSettings(c.store))!;
        await saveSettings(c.store, rest);
      });
      const refused = await fresh.owner('configure', { handle: 'another' });
      expect(refused).toMatchObject({ ok: false, error: 'invalid_argument' });
      expect((refused as { message: string }).message).toMatch(/set once/);
      expect((await saved(fresh))?.handle).toBeUndefined();
      expect(stack.relay.cards.get(fresh.aceId)!.card.handle).toBe('fresh');
    } finally { await configurer.close(); await fresh.client.close(); await other.client.close(); }
  });

  it('pay: CAIP-10 accounts, at most 8, distinct; [] clears; any change of the set needs ace:admission', async () => {
    const acct = (i: number) => `eip155:8453:0x${i.toString(16).padStart(40, '0')}`;
    const configurer = await connect(url, (await stack.service.grants.create({ aceId: agent.aceId, ownerHash: sha256Hex(agent.token), clientId: 'c', resource: url, scopes: [...DEFAULT_SCOPES, 'ace:configure'] })).access_token);
    const denied = { ok: false, error: 'insufficient_scope' };
    try {
      // Arguments are validated before the scope check.
      for (const pay of [['not-an-account'], [acct(1), acct(1)], Array.from({ length: 9 }, (_, i) => acct(i + 1)), ['eip155:8453:0xabc'.padEnd(200, 'f')]]) {
        expect(await configurer.call('ace_configure', { pay }), JSON.stringify(pay)).toMatchObject({ ok: false, error: 'invalid_argument' });
      }
      const pay = Array.from({ length: 8 }, (_, i) => acct(i + 1));
      // Adding accounts (from none) is gated for a configure-only client; the admission-holding client may.
      expect(await configurer.call('ace_configure', { pay })).toMatchObject(denied);
      expect(stack.relay.cards.get(agent.aceId)!.card.pay).toBeUndefined();
      expect((await agent.client.callOk('ace_configure', { pay })).pay).toEqual(pay);
      expect(stack.relay.cards.get(agent.aceId)!.card.pay).toEqual(pay);
      // The same set in another order is no change: not gated.
      expect((await configurer.callOk('ace_configure', { pay: [...pay].reverse(), card: { description: 'Scoped' } })).card.description).toBe('Scoped');
      // Replacing, removing or clearing an account is gated.
      for (const next of [[...pay.slice(1), acct(99)], pay.slice(1), []]) {
        expect(await configurer.call('ace_configure', { pay: next }), JSON.stringify(next)).toMatchObject(denied);
      }
      expect(new Set(stack.relay.cards.get(agent.aceId)!.card.pay)).toEqual(new Set(pay));
      expect(await agent.client.callOk('ace_configure', { pay: [] })).not.toHaveProperty('pay');
      expect(stack.relay.cards.get(agent.aceId)!.card.pay).toBeUndefined();
    } finally { await configurer.close(); }
  });

  it('a relay invalid_argument without any handle involved comes back as the relay said, without the set-once text', async () => {
    const plain = await createIdentity(stack.service, url);
    const route = stack.relay.route.bind(stack.relay);
    stack.relay.route = async (method, u, headers, body) => {
      if (u.pathname === '/v1/card' && method === 'POST') throw new ACEError('invalid_argument', 'refused');
      return route(method, u, headers, body);
    };
    try {
      const r = await plain.owner('configure', { card: { description: 'Plain 2' } });
      expect(r).toMatchObject({ ok: false, error: 'relay_rejected' });
      expect((r as { message: string }).message).not.toMatch(/set once/);
    } finally { stack.relay.route = route; await plain.client.close(); }
  });

  it('the hosted card tag is enforced on the published card record', async () => {
    expect((await agent.ownerOk('configure', { card: { description: 'Scoped', tags: ['helper'] } })).card.tags).toEqual(['helper', 'hosted']);
    expect(stack.relay.cards.get(agent.aceId)!.card.card.tags).toEqual(['helper', 'hosted']);
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
