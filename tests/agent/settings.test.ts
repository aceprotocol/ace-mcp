import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ProfileManifest } from '@ace-protocol/sdk';
import { createStack, type Stack } from '../helpers/stack.js';
import { provisionIdentity } from '../../src/identity/provision.js';
import { defaultSettings, hostedCard, loadSettings } from '../../src/agent/settings.js';
import { identityKeys } from '../../src/store/keyspace.js';
import { connect, createIdentity, startListening, type McpTestClient } from '../helpers/client.js';
import { sha256Hex } from '@ace-protocol/sdk';

const MANIFEST: ProfileManifest = {
  id: 'example:weather:1',
  messages: [{ type: 'example:weather:forecast:1', schema: { type: 'object', properties: { city: { type: 'string', maxLength: 64 } }, required: ['city'], additionalProperties: false } }],
};

let stack: Stack, url: string;
beforeAll(async () => { stack = await createStack(49); url = await startListening(stack.service); });
afterAll(() => stack?.close());

describe('hosted settings', () => {
  it('defaults to private text-only with the hosted tag; validates the card name and tag count', () => {
    expect(defaultSettings('Agent')).toMatchObject({ visibility: 'private', card: { name: 'Agent', tags: ['hosted'] }, profiles: ['text'], manifests: [], acceptProfiles: [] });
    expect(() => defaultSettings('')).toThrow();
    expect(() => defaultSettings('bad\u0000name')).toThrow();
    expect(() => hostedCard({ name: 'A', tags: Array.from({ length: 10 }, (_, i) => `t${i}`) })).toThrow(/at most 9/);
  });

  it('settings not saved when publish rejected (the SDK descriptor rules are the only check)', async () => {
    const { identity } = await provisionIdentity(stack.service.deps, { name: 'Strict' }, '127.0.0.1');
    const aceId = identity.getACEId();
    const saved = await stack.service.runtime.withIdentity(aceId, undefined, (c) => loadSettings(c.store));
    const refused = [
      { ...saved!, handle: 'alice' }, // a handle needs public visibility
      { ...saved!, acceptProfiles: ['ace:commerce:1'] }, // not installed
      { ...saved!, ext: { 'ace:commerce:1': { settlement: [{ method: 'stripe-link' }] } } }, // ext of an uninstalled profile
      { ...saved!, profiles: ['text', 'commerce'] as const, ext: { 'ace:commerce:1': { settlement: [{ method: 'cash' }] } } },
      { ...saved!, manifests: [{ ...MANIFEST, id: 'ace:weather:1' }] }, // reserved namespace
    ];
    for (const next of refused) {
      await expect(stack.service.runtime.withIdentity(aceId, undefined, (c) => c.updateSettings(() => next as never))).rejects.toThrow();
    }
    // A relay that refuses the descriptor leaves the saved settings unchanged too.
    const route = stack.relay.route.bind(stack.relay);
    stack.relay.route = async (method, u, headers, body) => {
      if (u.pathname === '/v1/descriptor' && method === 'POST') throw new Error('relay down');
      return route(method, u, headers, body);
    };
    try {
      await expect(stack.service.runtime.withIdentity(aceId, undefined, (c) => c.updateSettings((s) => ({ ...s, card: hostedCard({ name: 'Renamed' }) })))).rejects.toThrow();
    } finally {
      stack.relay.route = route;
    }
    expect(await stack.service.runtime.withIdentity(aceId, undefined, (c) => loadSettings(c.store))).toEqual(saved);
    expect(stack.relay.descriptors.get(aceId)!.descriptor.card.name).toBe('Strict');
    // A valid change publishes, then saves.
    await stack.service.runtime.withIdentity(aceId, undefined, (c) => c.updateSettings((s) => ({ ...s, visibility: 'public', handle: 'strict' })));
    expect((await stack.service.runtime.withIdentity(aceId, undefined, (c) => loadSettings(c.store)))?.handle).toBe('strict');
    expect(stack.relay.descriptors.get(aceId)!.descriptor.handle).toBe('strict');
  });
});

describe('concurrent settings changes', () => {
  /**
   * A configure-only client (no ace:admission) whose call loaded the identity while it was public and auto-accepting,
   * racing the owner who tightens it to private with no auto-accept: the owner's change lands between the client's
   * load and its write. `vault.load` is held for the client's call only (its settings snapshot is read alongside it).
   */
  async function race(clientArgs: Record<string, unknown>) {
    const agent = await createIdentity(stack.service, url, 'Racer');
    await agent.ownerOk('configure', { visibility: 'public', acceptProfiles: ['ace:text:1'] });
    const client: McpTestClient = await connect(url, (await stack.service.grants.create({
      aceId: agent.aceId, ownerHash: sha256Hex(agent.token), clientId: 'c', resource: url, scopes: ['ace:read', 'ace:configure'],
    })).access_token);
    const vault = stack.service.deps.vault;
    const load = vault.load.bind(vault);
    let loaded!: () => void, release!: () => void;
    const clientLoaded = new Promise<void>((r) => { loaded = r; });
    const ownerDone = new Promise<void>((r) => { release = r; });
    let armed = true;
    vault.load = async (id) => {
      const v = await load(id);
      if (armed && id === agent.aceId) { armed = false; loaded(); await ownerDone; }
      return v;
    };
    try {
      const pending = client.call('ace_configure', clientArgs);
      await clientLoaded;
      await agent.ownerOk('configure', { visibility: 'private', acceptProfiles: [] });
      release();
      const result = await pending;
      const saved = await stack.service.runtime.withIdentity(agent.aceId, undefined, (c) => loadSettings(c.store));
      return { result, saved: saved!, published: stack.relay.descriptors.get(agent.aceId)!.descriptor };
    } finally {
      vault.load = load;
      await client.close(); await agent.client.close();
    }
  }

  it('a rename-only change merges onto the fresh settings and never restores what the owner tightened', async () => {
    const { result, saved, published } = await race({ card: { name: 'Renamed' } });
    expect(result.ok).toBe(true);
    expect(saved).toMatchObject({ visibility: 'private', acceptProfiles: [], card: { name: 'Renamed' } });
    expect(published).toMatchObject({ visibility: 'private', card: { name: 'Renamed' } });
  });

  it('the admission check runs against the fresh settings: re-sending the stale public state needs ace:admission', async () => {
    const { result, saved } = await race({ visibility: 'public', acceptProfiles: ['ace:text:1'] });
    expect(result).toMatchObject({ ok: false, error: 'insufficient_scope' });
    expect(saved).toMatchObject({ visibility: 'private', acceptProfiles: [] });
  });

  it('an owner change outwaits a change in flight, and tool changes stand aside while it waits', async () => {
    const { identity } = await provisionIdentity(stack.service.deps, { name: 'Owned' }, '127.0.0.1');
    const aceId = identity.getACEId();
    const { runtime } = stack.service;
    const k = identityKeys(aceId);
    const rename = (name: string, owner: boolean) => runtime.withIdentity(aceId, undefined, (c) => c.updateSettings((s) => ({ ...s, card: hostedCard({ name }) })), { owner });
    // A change in flight holds the settings lock past the tool calls' 2 s wait.
    await stack.redis.set(`${k.locks}mcp-settings`, 'in-flight', 'PX', 60_000);
    const owner = rename('Owner', true);
    while (Number(await stack.redis.get(k.ownerWaiting) ?? 0) === 0) await new Promise((r) => setTimeout(r, 10));
    await expect(rename('Client', false)).rejects.toMatchObject({ code: 'lock_busy' });
    await new Promise((r) => setTimeout(r, 2_500));
    await stack.redis.del(`${k.locks}mcp-settings`);
    await expect(owner).resolves.toMatchObject({ card: { name: 'Owner' } });
    expect(Number(await stack.redis.get(k.ownerWaiting))).toBe(0);
    await expect(rename('Client', false)).resolves.toMatchObject({ card: { name: 'Client' } });
  }, 15_000);
});
