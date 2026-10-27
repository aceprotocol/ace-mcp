import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DELEGATION_PROFILE_ID, SoftwareIdentity, createDelegationCredential, type ProfileManifest } from '@ace-protocol/sdk';
import { createStack, type Stack } from '../helpers/stack.js';
import { provisionIdentity } from '../../src/identity/provision.js';
import { defaultSettings, hostedCard, loadSettings, publishedProfiles } from '../../src/agent/settings.js';
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
  it('defaults to closed, unlisted, text-only with the hosted tag; validates the card (no name) and tag count', () => {
    expect(defaultSettings()).toEqual({ contact: 'closed', listed: false, card: { tags: ['hosted'] }, profiles: ['text'], manifests: [], acceptProfiles: [], delegations: [], erc8004: [] });
    expect(() => hostedCard({ name: 'Agent' })).toThrow(/only description, image and tags/);
    expect(() => hostedCard({ description: 'bad\u0000text' })).toThrow();
    expect(() => hostedCard({ tags: Array.from({ length: 10 }, (_, i) => `t${i}`) })).toThrow(/at most 9/);
  });

  it('publishes live delegation credentials in ext["ace:delegation:1"] with the delegation profile, and nothing while none is live', async () => {
    const [a, b, subject] = await Promise.all([SoftwareIdentity.generate(), SoftwareIdentity.generate(), SoftwareIdentity.generate()]);
    const now = Math.floor(Date.now() / 1000);
    const live = await createDelegationCredential(a, subject.getACEId(), { now, ttl: 600 });
    const expired = await createDelegationCredential(b, subject.getACEId(), { now, ttl: 60 }); // expired at `later`
    const later = now + 120;
    const ext = { 'ace:commerce:1': { settlement: [{ method: 'stripe-link' }] } };
    const base = { ...defaultSettings(), profiles: ['text', 'commerce'] as const, manifests: [MANIFEST], ext };
    expect(publishedProfiles({ ...base, profiles: [...base.profiles], delegations: [live, expired] }, later)).toEqual({
      profiles: ['text', 'commerce', 'delegation', MANIFEST], ext: { ...ext, [DELEGATION_PROFILE_ID]: { credentials: [live] } },
    });
    expect(publishedProfiles({ ...base, profiles: [...base.profiles], delegations: [expired] }, later)).toEqual({ profiles: ['text', 'commerce', MANIFEST], ext });
    expect(publishedProfiles(defaultSettings(), now)).toEqual({ profiles: ['text'] });
  });

  it('settings not saved when publish rejected (the SDK descriptor rules are the only check)', async () => {
    const { identity } = await provisionIdentity(stack.service.deps, '127.0.0.1');
    const aceId = identity.getACEId();
    const saved = await stack.service.runtime.withIdentity(aceId, undefined, (c) => loadSettings(c.store));
    const refused = [
      { ...saved!, handle: 'Not A Handle' }, // the handle grammar
      { ...saved!, handle: 'not_a_handle' },
      { ...saved!, card: { name: 'Named', tags: ['hosted'] } }, // a card carries no name
      { ...saved!, pay: ['not-caip10'] }, // card record rules
      { ...saved!, erc8004: [{ agentRegistry: 'eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432', agentId: '01' }] },
      { ...saved!, acceptProfiles: ['ace:commerce:1'] }, // not installed
      { ...saved!, ext: { 'ace:commerce:1': { settlement: [{ method: 'stripe-link' }] } } }, // ext of an uninstalled profile
      { ...saved!, profiles: ['text', 'commerce'] as const, ext: { 'ace:commerce:1': { settlement: [{ method: 'cash' }] } } },
      { ...saved!, manifests: [{ ...MANIFEST, id: 'ace:weather:1' }] }, // reserved namespace
    ];
    for (const next of refused) {
      await expect(stack.service.runtime.withIdentity(aceId, undefined, (c) => c.updateSettings(() => next as never))).rejects.toThrow();
    }
    // A relay that refuses the card record (posted first) or the descriptor leaves the saved settings unchanged too;
    // a refused card record leaves the published descriptor unchanged.
    const route = stack.relay.route.bind(stack.relay);
    const descriptorAt = stack.relay.descriptors.get(aceId)!.descriptor.issuedAt;
    for (const path of ['/v1/card', '/v1/descriptor']) {
      stack.relay.route = async (method, u, headers, body) => {
        if (u.pathname === path && method === 'POST') throw new Error('relay down');
        return route(method, u, headers, body);
      };
      try {
        await expect(stack.service.runtime.withIdentity(aceId, undefined, (c) => c.updateSettings((s) => ({ ...s, card: hostedCard({ description: 'Renamed' }) })))).rejects.toThrow();
      } finally {
        stack.relay.route = route;
      }
      expect(await stack.service.runtime.withIdentity(aceId, undefined, (c) => loadSettings(c.store))).toEqual(saved);
      if (path === '/v1/card') {
        expect(stack.relay.cards.get(aceId)!.card.card).toEqual({ tags: ['hosted'] });
        expect(stack.relay.descriptors.get(aceId)!.descriptor.issuedAt).toBe(descriptorAt);
      }
    }
    // A valid change publishes, then saves.
    await stack.service.runtime.withIdentity(aceId, undefined, (c) => c.updateSettings((s) => ({ ...s, contact: 'open', handle: 'strict' })));
    expect(await stack.service.runtime.withIdentity(aceId, undefined, (c) => loadSettings(c.store))).toMatchObject({ handle: 'strict', contact: 'open' });
    expect(stack.relay.cards.get(aceId)!.card).toMatchObject({ handle: 'strict', contact: 'open' });
  });
});

describe('concurrent settings changes', () => {
  /**
   * A configure-only client (no ace:admission) whose call loaded the identity while it was open, listed and
   * auto-accepting, racing the owner who tightens it to closed, unlisted with no auto-accept: the owner's change lands between the client's
   * load and its write. `vault.load` is held for the client's call only (its settings snapshot is read alongside it).
   */
  async function race(clientArgs: Record<string, unknown>) {
    const agent = await createIdentity(stack.service, url);
    await agent.ownerOk('configure', { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
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
      await agent.ownerOk('configure', { contact: 'closed', listed: false, acceptProfiles: [] });
      release();
      const result = await pending;
      const saved = await stack.service.runtime.withIdentity(agent.aceId, undefined, (c) => loadSettings(c.store));
      return { result, saved: saved!, published: stack.relay.cards.get(agent.aceId)!.card };
    } finally {
      vault.load = load;
      await client.close(); await agent.client.close();
    }
  }

  it('a card-only change merges onto the fresh settings and never restores what the owner tightened', async () => {
    const { result, saved, published } = await race({ card: { description: 'Renamed' } });
    expect(result.ok).toBe(true);
    expect(saved).toMatchObject({ contact: 'closed', listed: false, acceptProfiles: [], card: { description: 'Renamed' } });
    expect(published).toMatchObject({ contact: 'closed', listed: false, card: { description: 'Renamed' } });
  });

  it('the admission check runs against the fresh settings: re-sending the stale open state needs ace:admission', async () => {
    const { result, saved } = await race({ contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
    expect(result).toMatchObject({ ok: false, error: 'insufficient_scope' });
    expect(saved).toMatchObject({ contact: 'closed', listed: false, acceptProfiles: [] });
  });

  it('an owner change outwaits a change in flight, and tool changes stand aside while it waits', async () => {
    const { identity } = await provisionIdentity(stack.service.deps, '127.0.0.1');
    const aceId = identity.getACEId();
    const { runtime } = stack.service;
    const k = identityKeys(aceId);
    const rename = (description: string, owner: boolean) => runtime.withIdentity(aceId, undefined, (c) => c.updateSettings((s) => ({ ...s, card: hostedCard({ description }) })), { owner });
    // A change in flight holds the settings lock past the tool calls' 2 s wait.
    await stack.redis.set(`${k.locks}mcp-settings`, 'in-flight', 'PX', 60_000);
    const owner = rename('Owner', true);
    while (Number(await stack.redis.get(k.ownerWaiting) ?? 0) === 0) await new Promise((r) => setTimeout(r, 10));
    await expect(rename('Client', false)).rejects.toMatchObject({ code: 'lock_busy' });
    await new Promise((r) => setTimeout(r, 2_500));
    await stack.redis.del(`${k.locks}mcp-settings`);
    await expect(owner).resolves.toMatchObject({ card: { description: 'Owner' } });
    expect(Number(await stack.redis.get(k.ownerWaiting))).toBe(0);
    await expect(rename('Client', false)).resolves.toMatchObject({ card: { description: 'Client' } });
  }, 15_000);
});
