import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SoftwareIdentity, createDelegationCredential } from '@ace-protocol/sdk';
import { createStack, type Stack } from '../helpers/stack.js';
import { createIdentity, startListening, type HostedTestAgent } from '../helpers/client.js';

let stack: Stack, url: string, issuer: HostedTestAgent, subject: HostedTestAgent;
const REGISTRY = 'eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432';

beforeAll(async () => {
  stack = await createStack(32);
  url = await startListening(stack.service);
  issuer = await createIdentity(stack.service, url, 'Controller');
  subject = await createIdentity(stack.service, url, 'Delegate');
});
afterAll(async () => { await issuer?.client.close(); await subject?.client.close(); await stack?.close(); });

const published = (a: HostedTestAgent) => stack.relay.descriptors.get(a.aceId)!.descriptor;

describe('ace_delegation', () => {
  it('issues a credential for a subject, which attaches it to its descriptor; detach removes it', async () => {
    const { entry, expiresAt } = await issuer.client.callOk('ace_delegation', { action: 'issue', subject: subject.aceId, ttlSeconds: 3600 });
    expect(entry.credential).toMatchObject({ issuer: issuer.aceId, subject: subject.aceId, expiresAt });
    expect(await issuer.client.call('ace_delegation', { action: 'attach', entry })).toMatchObject({ ok: false, error: 'invalid_authorization' }); // not the subject

    expect(await subject.client.callOk('ace_delegation', { action: 'attach', entry })).toMatchObject({ issuer: issuer.aceId, status: 'published' });
    expect(published(subject).delegations).toMatchObject([{ credential: { issuer: issuer.aceId, subject: subject.aceId } }]);
    expect((await subject.client.callOk('ace_identity')).delegations).toEqual([{ issuer: issuer.aceId, expiresAt }]);
    expect((await subject.client.callOk('ace_delegation', { action: 'list' })).delegations).toMatchObject([{ issuer: issuer.aceId, live: true }]);

    // Others see it after a lookup (any registered identity's live descriptor resolves).
    await subject.ownerOk('configure', { contact: 'open', listed: true });
    const seen = await issuer.client.callOk('ace_network', { action: 'lookup', peer: subject.aceId });
    expect(seen.agent.delegations).toEqual([{ issuer: issuer.aceId, expiresAt }]);

    await subject.client.callOk('ace_delegation', { action: 'detach', issuer: issuer.aceId });
    expect(published(subject).delegations).toBeUndefined();
  });

  it('refuses forged or tampered credentials', async () => {
    const outsider = await SoftwareIdentity.generate();
    const credential = await createDelegationCredential(outsider, subject.aceId, { ttl: 600 });
    expect(await subject.client.call('ace_delegation', { action: 'attach', entry: { kel: (await SoftwareIdentity.generate()).getKel(), credential } }))
      .toMatchObject({ ok: false, error: 'invalid_authorization' });
    expect(await subject.client.call('ace_delegation', { action: 'attach', entry: { kel: outsider.getKel(), credential: { ...credential, expiresAt: credential.expiresAt + 1 } } }))
      .toMatchObject({ ok: false, error: 'invalid_authorization' });
    expect(await subject.client.callOk('ace_delegation', { action: 'attach', entry: { kel: outsider.getKel(), credential } })).toMatchObject({ issuer: outsider.getACEId() });
  });
});

describe('ace_erc8004', () => {
  it('attaches and detaches a binding on the signed descriptor and verifies the reverse direction', async () => {
    expect(await subject.client.callOk('ace_erc8004', { action: 'attach', agentRegistry: REGISTRY, agentId: '42' })).toMatchObject({ erc8004: [{ agentRegistry: REGISTRY, agentId: '42' }] });
    expect(published(subject).erc8004).toEqual([{ agentRegistry: REGISTRY, agentId: '42' }]);
    expect((await subject.client.callOk('ace_erc8004', { action: 'list' })).erc8004).toHaveLength(1);
    expect(await subject.client.call('ace_erc8004', { action: 'attach', agentRegistry: 'not-caip10', agentId: '1' })).toMatchObject({ ok: false, error: 'invalid_authorization' });
    expect(await subject.client.call('ace_erc8004', { action: 'attach', agentRegistry: REGISTRY, agentId: '01' })).toMatchObject({ ok: false, error: 'invalid_authorization' });

    const registration = { type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1', name: 'Delegate', services: [{ name: 'ACE', endpoint: subject.aceId }] };
    expect((await issuer.client.callOk('ace_erc8004', { action: 'verify', registration, aceId: subject.aceId })).bound).toBe(true);
    expect((await issuer.client.callOk('ace_erc8004', { action: 'verify', registration })).bound).toBe(false); // names the subject, not the caller

    await subject.client.callOk('ace_erc8004', { action: 'detach', agentRegistry: REGISTRY, agentId: '42' });
    expect(published(subject).erc8004).toBeUndefined();
  });
});
