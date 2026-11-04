import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DELEGATION_PROFILE_ID, SoftwareIdentity, createDelegationCredential, verifyDelegationCredential } from '@ace-protocol/sdk';
import { createStack, type Stack } from '../helpers/stack.js';
import { createIdentity, startListening, type HostedTestAgent } from '../helpers/client.js';

let stack: Stack, url: string, issuer: HostedTestAgent, subject: HostedTestAgent;
const REGISTRY = 'eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432';
const now = () => Math.floor(Date.now() / 1000);

beforeAll(async () => {
  stack = await createStack(32);
  url = await startListening(stack.service);
  issuer = await createIdentity(stack.service, url);
  subject = await createIdentity(stack.service, url);
});
afterAll(async () => { await issuer?.client.close(); await subject?.client.close(); await stack?.close(); });

const published = (a: HostedTestAgent) => stack.relay.descriptors.get(a.aceId)!.descriptor;
const publishedCard = (a: HostedTestAgent) => stack.relay.cards.get(a.aceId)!.card;

describe('ace_delegation', () => {
  it('issues a credential signed by the issuer; the subject publishes it in its ace:delegation:1 ext; detach removes it', async () => {
    const { credential, expiresAt } = await issuer.client.callOk('ace_delegation', { action: 'issue', subject: subject.aceId, ttlSeconds: 3600 });
    expect(credential).toMatchObject({ issuer: issuer.aceId, subject: subject.aceId, expiresAt });
    // The signature verifies under the issuer's KEL with action ace:delegation:1.
    expect(verifyDelegationCredential(credential, stack.relay.kels.get(issuer.aceId)!, now())).toEqual(credential);
    expect(await issuer.client.call('ace_delegation', { action: 'attach', credential })).toMatchObject({ ok: false, error: 'invalid_authorization' }); // not the subject

    expect(await subject.client.callOk('ace_delegation', { action: 'attach', credential })).toMatchObject({ issuer: issuer.aceId, expiresAt, status: 'published' });
    expect(published(subject).profiles.map((p) => p.id)).toContain(DELEGATION_PROFILE_ID);
    expect(published(subject).ext).toEqual({ [DELEGATION_PROFILE_ID]: { credentials: [credential] } });
    expect((await subject.client.callOk('ace_identity')).delegations).toEqual([{ issuer: issuer.aceId, expiresAt }]);
    expect((await subject.client.callOk('ace_delegation', { action: 'list' })).delegations).toMatchObject([{ issuer: issuer.aceId, live: true }]);

    // Others see it in the descriptor ext after a lookup.
    await subject.ownerOk('configure', { contact: 'open', listed: true });
    const seen = await issuer.client.callOk('ace_network', { action: 'lookup', peer: subject.aceId });
    expect(seen.agent.ext).toEqual({ [DELEGATION_PROFILE_ID]: { credentials: [credential] } });

    await subject.client.callOk('ace_delegation', { action: 'detach', issuer: issuer.aceId });
    expect(published(subject).ext).toBeUndefined();
    expect(published(subject).profiles.map((p) => p.id)).not.toContain(DELEGATION_PROFILE_ID);
  });

  it('keeps an acceptProfiles entry for ace:delegation:1 valid: detaching the last credential under it is refused', async () => {
    const { credential } = await issuer.client.callOk('ace_delegation', { action: 'issue', subject: subject.aceId, ttlSeconds: 600 });
    await subject.client.callOk('ace_delegation', { action: 'attach', credential });
    await subject.ownerOk('configure', { acceptProfiles: [DELEGATION_PROFILE_ID] });
    expect(await subject.client.call('ace_delegation', { action: 'detach', issuer: issuer.aceId })).toMatchObject({ ok: false, error: 'invalid_argument' });
    expect(published(subject).ext).toEqual({ [DELEGATION_PROFILE_ID]: { credentials: [credential] } });
    await subject.ownerOk('configure', { acceptProfiles: [] });
    await subject.client.callOk('ace_delegation', { action: 'detach', issuer: issuer.aceId });
    expect(published(subject).profiles.map((p) => p.id)).not.toContain(DELEGATION_PROFILE_ID);
  });

  it('refuses tampered credentials and credentials of an issuer it cannot look up', async () => {
    const { credential: issued } = await issuer.client.callOk('ace_delegation', { action: 'issue', subject: subject.aceId, ttlSeconds: 600 });
    expect(await subject.client.call('ace_delegation', { action: 'attach', credential: { ...issued, expiresAt: issued.expiresAt + 1 } }))
      .toMatchObject({ ok: false, error: 'invalid_authorization' });
    const outsider = await SoftwareIdentity.generate();
    const credential = await createDelegationCredential(outsider, subject.aceId, { ttl: 600 });
    expect(await subject.client.call('ace_delegation', { action: 'attach', credential })).toMatchObject({ ok: false, error: 'unknown_peer' });
    expect(published(subject).ext).toBeUndefined();
  });
});

describe('ace_erc8004', () => {
  it('attaches and detaches a binding on the published card record and verifies the reverse direction', async () => {
    expect(await subject.client.callOk('ace_erc8004', { action: 'attach', agentRegistry: REGISTRY, agentId: '42' })).toMatchObject({ erc8004: [{ agentRegistry: REGISTRY, agentId: '42' }] });
    expect(publishedCard(subject).erc8004).toEqual([{ agentRegistry: REGISTRY, agentId: '42' }]);
    expect((published(subject) as unknown as Record<string, unknown>).erc8004).toBeUndefined();
    expect((await subject.client.callOk('ace_identity')).erc8004).toEqual([{ agentRegistry: REGISTRY, agentId: '42' }]);
    expect((await issuer.client.callOk('ace_network', { action: 'lookup', peer: subject.aceId })).card.erc8004).toEqual([{ agentRegistry: REGISTRY, agentId: '42' }]);
    expect((await subject.client.callOk('ace_erc8004', { action: 'list' })).erc8004).toHaveLength(1);
    expect(await subject.client.call('ace_erc8004', { action: 'attach', agentRegistry: 'not-caip10', agentId: '1' })).toMatchObject({ ok: false, error: 'invalid_authorization' });
    expect(await subject.client.call('ace_erc8004', { action: 'attach', agentRegistry: REGISTRY, agentId: '01' })).toMatchObject({ ok: false, error: 'invalid_authorization' });

    const registration = { type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1', name: 'Delegate', services: [{ name: 'ACE', endpoint: subject.aceId }] };
    expect((await issuer.client.callOk('ace_erc8004', { action: 'verify', registration, aceId: subject.aceId })).bound).toBe(true);
    expect((await issuer.client.callOk('ace_erc8004', { action: 'verify', registration })).bound).toBe(false); // names the subject, not the caller

    await subject.client.callOk('ace_erc8004', { action: 'detach', agentRegistry: REGISTRY, agentId: '42' });
    expect(publishedCard(subject).erc8004).toBeUndefined();
  });
});
