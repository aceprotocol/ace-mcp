import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createStack, type Stack } from '../helpers/stack.js';
import { createIdentity, eventually, startListening, type HostedTestAgent } from '../helpers/client.js';
import { AgentWorkers } from '../../src/agent/workers.js';

let stack: Stack, url: string, alice: HostedTestAgent, bob: HostedTestAgent;
const silent = { error: () => undefined };

beforeAll(async () => {
  stack = await createStack(30);
  url = await startListening(stack.service);
  alice = await createIdentity(stack.service, url);
  bob = await createIdentity(stack.service, url);
});
afterAll(async () => {
  await alice?.client.close();
  await bob?.client.close();
  await stack?.close();
});

const outboxStatus = async (a: HostedTestAgent, messageId: string) =>
  ((await a.client.callOk('ace_outbox', { action: 'list' })).messages as Array<{ messageId: string; status: string; code?: string }>).find((m) => m.messageId === messageId);

describe('two hosted identities through the relay (tool-call receive path)', () => {
  it('starts closed and unlisted: not in the directory, no handle, strangers cannot send', async () => {
    const me = await alice.client.callOk('ace_identity');
    expect(me).toMatchObject({ aceId: alice.aceId, contact: 'closed', listed: false, custody: 'hosted', card: { tags: ['hosted'] } });
    expect(me).not.toHaveProperty('handle');
    expect(me.profiles.map((p: { id: string }) => p.id)).toEqual(['ace:core:1', 'ace:text:1']);
    expect((await bob.client.callOk('ace_network', { action: 'discover' })).cards).toEqual([]);
    expect(stack.relay.cards.get(alice.aceId)?.card).toMatchObject({ contact: 'closed', listed: false });
    expect(await bob.client.call('ace_network', { action: 'connect', peer: alice.aceId })).toMatchObject({ ok: false, error: 'not_permitted' });
  });

  it('contact request, explicit accept, send, inbox read + ack, and the receipt marks the send delivered', async () => {
    const pay = ['eip155:8453:0x00000000000000000000000000000000000000a1', 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7S3P4HxJpyyigGzodYwHtCxZyUQe9JiBMHyRWXArAaKv'];
    expect(await alice.ownerOk('configure', { contact: 'open', listed: true, handle: 'alice', pay, card: { description: 'Answers questions', tags: ['qa'] } }))
      .toMatchObject({ status: 'published', handle: 'alice', address: '@alice@relay.test', pay, contact: 'open', listed: true, card: { tags: ['qa', 'hosted'] } });
    // discover returns card views (aceId, address, card), filtered by tag or the profile hint; lookup before connecting
    const found = await bob.client.callOk('ace_network', { action: 'discover', profile: 'ace:text:1' });
    expect(found.cards).toEqual([{ aceId: alice.aceId, home: 'https://relay.test', handle: 'alice', address: '@alice@relay.test',
      card: { description: 'Answers questions', tags: ['qa', 'hosted'] }, pay, contact: 'open', listed: true }]);
    expect(found.untrusted).toEqual(expect.arrayContaining(['cards[].card']));
    expect((await bob.client.callOk('ace_network', { action: 'discover', tag: 'qa' })).cards.map((c: { aceId: string }) => c.aceId)).toEqual([alice.aceId]);
    expect((await bob.client.callOk('ace_network', { action: 'discover', tag: 'legal' })).cards).toEqual([]);
    expect(await bob.client.call('ace_network', { action: 'discover', tag: 'Not A Tag' })).toMatchObject({ ok: false, error: 'invalid_argument' });
    const looked = await bob.client.callOk('ace_network', { action: 'lookup', peer: '@alice@relay.test' });
    expect(looked.agent.aceId).toBe(alice.aceId);
    expect(looked.card).toEqual({ aceId: alice.aceId, home: 'https://relay.test', handle: 'alice', address: '@alice@relay.test', card: { description: 'Answers questions', tags: ['qa', 'hosted'] }, pay, contact: 'open', listed: true });
    expect(looked.untrusted).toContain('card');
    expect((await bob.client.callOk('ace_network', { action: 'lookup', peer: alice.aceId })).card).toMatchObject({ handle: 'alice', contact: 'open' });
    // a typed address may omit the leading @ and use any case
    expect((await bob.client.callOk('ace_network', { action: 'lookup', peer: 'Alice@Relay.Test' })).agent.aceId).toBe(alice.aceId);
    // a card carries no name
    expect(await alice.owner('configure', { card: { name: 'Alice' } })).toMatchObject({ ok: false, error: 'invalid_authorization' });

    expect(await bob.client.callOk('ace_network', { action: 'connect', peer: alice.aceId, note: 'hello from bob' })).toMatchObject({ status: 'pending', profile: 'ace:text:1' });
    expect((await alice.client.callOk('ace_inbox', {})).messages).toEqual([]); // processes the contact packet
    const { requests } = await alice.client.callOk('ace_network', { action: 'requests' });
    expect(requests).toMatchObject([{ from: bob.aceId, profile: 'ace:text:1', note: 'hello from bob', agent: { aceId: bob.aceId } }]);
    await alice.client.callOk('ace_network', { action: 'accept', peer: bob.aceId });
    await bob.client.callOk('ace_inbox', {}); // processes `accepted`
    expect((await bob.client.callOk('ace_network', { action: 'peers' })).peers).toMatchObject([{ aceId: alice.aceId, status: 'admitted', canSend: true }]);

    const sent = await bob.client.callOk('ace_send', { to: alice.aceId, type: 'ace:text:1', body: { message: 'hi alice' } });
    expect(sent).toMatchObject({ status: 'pending', attempts: 1, to: alice.aceId });
    const read = await alice.client.callOk('ace_inbox', {});
    expect(read.messages).toMatchObject([{ from: bob.aceId, type: 'ace:text:1', body: { message: 'hi alice' }, read: false }]);
    expect((await alice.client.callOk('ace_inbox', {})).messages).toHaveLength(1); // reading does not consume
    expect((await alice.client.callOk('ace_inbox', { action: 'ack', messages: [{ from: bob.aceId, messageId: sent.messageId }] })).acknowledged).toBe(1);
    expect((await alice.client.callOk('ace_inbox', {})).messages).toEqual([]);
    expect((await alice.client.callOk('ace_inbox', { unreadOnly: false })).messages).toHaveLength(1);

    await bob.client.callOk('ace_inbox', {}); // processes the receipt
    expect(await outboxStatus(bob, sent.messageId)).toMatchObject({ status: 'delivered' });

    const reply = await alice.client.callOk('ace_send', { to: bob.aceId, type: 'ace:text:1', body: { message: 'hi bob' } });
    expect((await bob.client.callOk('ace_inbox', { from: alice.aceId })).messages[0].body).toEqual({ message: 'hi bob' });
    await alice.client.callOk('ace_inbox', {});
    expect(await outboxStatus(alice, reply.messageId)).toMatchObject({ status: 'delivered' });
  });

  it('closed pairing: invite admits the invitee; import_invitation never admits; connect completes it', async () => {
    const carol = await createIdentity(stack.service, url);
    const dave = await createIdentity(stack.service, url);
    try {
      const { source } = await dave.client.callOk('ace_network', { action: 'publish' });
      const inv = await carol.client.callOk('ace_network', { action: 'invite', source });
      expect(inv).toMatchObject({ peer: dave.aceId, profile: 'ace:text:1', invitation: { agent: { descriptor: { aceId: carol.aceId } } } });
      expect((await carol.client.callOk('ace_network', { action: 'peers' })).peers).toMatchObject([{ aceId: dave.aceId, status: 'admitted' }]);
      // only the named peer can import it
      expect(await alice.client.call('ace_network', { action: 'import_invitation', invitation: inv.invitation })).toMatchObject({ ok: false, error: 'invalid_authorization' });
      expect(await dave.client.callOk('ace_network', { action: 'import_invitation', invitation: inv.invitation })).toMatchObject({ agent: { aceId: carol.aceId }, permit: true });
      expect((await dave.client.callOk('ace_network', { action: 'peers' })).peers).toEqual([]); // never admits
      await dave.client.callOk('ace_network', { action: 'connect', peer: carol.aceId });
      await carol.client.callOk('ace_inbox', {}); // the admitted invitee's request is accepted
      await dave.client.callOk('ace_inbox', {});
      expect((await dave.client.callOk('ace_network', { action: 'peers' })).peers).toMatchObject([{ aceId: carol.aceId, status: 'admitted', canSend: true }]);
      const sent = await dave.client.callOk('ace_send', { to: carol.aceId, type: 'ace:text:1', body: { message: 'private hello' } });
      expect((await carol.client.callOk('ace_inbox', {})).messages).toMatchObject([{ messageId: sent.messageId, from: dave.aceId }]);
    } finally {
      await carol.client.close(); await dave.client.close();
    }
  });

  it('refuses unknown types, self-sends and settings fields outside ace_configure', async () => {
    expect(await bob.client.call('ace_send', { to: alice.aceId, type: 'ace:commerce:rfq:1', threadId: 't', body: { need: 'x' } })).toMatchObject({ ok: false, error: 'unsupported_schema' });
    expect(await bob.client.call('ace_send', { to: bob.aceId, type: 'ace:text:1', body: { message: 'me' } })).toMatchObject({ ok: false, error: 'invalid_argument' });
    expect(await bob.client.call('ace_send', { to: alice.aceId, type: 'ace:text:1', body: { wrong: 1 } })).toMatchObject({ ok: false, error: 'invalid_body' });
    expect(await bob.client.call('ace_network', { action: 'discover', visibility: 'public' })).toMatchObject({ ok: false, error: 'invalid_argument' });
    expect(await bob.client.call('ace_configure', { visibility: 'public' })).toMatchObject({ ok: false, error: 'invalid_argument' }); // replaced by contact / listed
    expect(await bob.client.call('ace_threads', {})).toMatchObject({ ok: false, error: 'invalid_argument' });
  });

  it('commerce: only when installed; the receiver rejects an uninstalled schema; thread state and allowed next types', async () => {
    await bob.client.callOk('ace_configure', { profiles: ['text', 'commerce'] });
    const early = await bob.client.callOk('ace_send', { to: alice.aceId, type: 'ace:commerce:rfq:1', threadId: randomUUID(), body: { need: 'a logo' } });
    await alice.client.callOk('ace_inbox', {});
    await bob.client.callOk('ace_inbox', {});
    expect(await outboxStatus(bob, early.messageId)).toMatchObject({ status: 'rejected', code: 'unsupported_schema' });

    await alice.client.callOk('ace_configure', { profiles: ['text', 'commerce'], ext: { 'ace:commerce:1': { settlement: [{ method: 'stablecoin', asset: 'eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913' }] } } });
    expect(stack.relay.descriptors.get(alice.aceId)!.descriptor.ext).toMatchObject({ 'ace:commerce:1': { settlement: [{ method: 'stablecoin' }] } });
    const threadId = randomUUID();
    const rfq = await bob.client.callOk('ace_send', { to: alice.aceId, type: 'ace:commerce:rfq:1', threadId, body: { need: 'a logo', currency: 'USDC' } });
    expect(rfq.threadState).toBeUndefined(); // the buyer's thread starts with the seller's delivered receipt
    expect(await bob.client.call('ace_send', { to: alice.aceId, type: 'ace:commerce:rfq:1', threadId, body: { need: 'again' } }))
      .toMatchObject({ ok: false, error: 'thread_busy', retryable: true });
    const got = await alice.client.callOk('ace_inbox', { threadId });
    expect(got.messages).toMatchObject([{ type: 'ace:commerce:rfq:1', threadId, threadState: 'requested' }]);
    const thread = await alice.client.callOk('ace_threads', { threadId });
    expect(thread).toMatchObject({ state: 'requested', role: 'seller', peerAceId: bob.aceId });
    expect(thread.allowedNextTypes.sort()).toEqual(['ace:commerce:offer:1', 'ace:commerce:reject:1']);
    expect(await alice.client.call('ace_send', { to: bob.aceId, type: 'ace:commerce:accept:1', threadId, body: { offerId: rfq.messageId } }))
      .toMatchObject({ ok: false, error: 'transition_not_allowed' });
    const offer = await alice.client.callOk('ace_send', { to: bob.aceId, type: 'ace:commerce:offer:1', threadId, body: { price: '25', currency: 'USDC' } });
    expect(offer.threadState).toBe('requested'); // committed when bob's receipt arrives
    expect((await bob.client.callOk('ace_threads', {})).threads.find((t: { threadId: string }) => t.threadId === threadId)).toBeUndefined();
    await bob.client.callOk('ace_inbox', {}); // the rfq's receipt, then the offer
    expect((await bob.client.callOk('ace_threads', { threadId })).state).toBe('offered');
    await alice.client.callOk('ace_inbox', {}); // the offer's receipt
    expect((await alice.client.callOk('ace_threads', { threadId })).state).toBe('offered');
  });

  it('block refuses delivery at the relay; unblock clears it', async () => {
    await alice.client.callOk('ace_network', { action: 'block', peer: bob.aceId });
    expect(stack.relay.blocks.get(`${alice.aceId}|${bob.aceId}`)).toEqual({ blocked: true, revision: 1 });
    const sent = await bob.client.callOk('ace_send', { to: alice.aceId, type: 'ace:text:1', body: { message: 'blocked?' } });
    expect(sent).toMatchObject({ status: 'pending', code: 'not_permitted' });
    expect((await bob.client.callOk('ace_outbox', { action: 'abandon', messageId: sent.messageId })).status).toBe('expired');
    await alice.client.callOk('ace_network', { action: 'unblock', peer: bob.aceId });
    expect(stack.relay.blocks.get(`${alice.aceId}|${bob.aceId}`)).toEqual({ blocked: false, revision: 2 });
    expect((await alice.client.callOk('ace_network', { action: 'peers' })).peers.find((p: { aceId: string }) => p.aceId === bob.aceId)).toBeUndefined();
  });
});

describe('resident workers', () => {
  it('follow the relay over SSE, store messages, send receipts, and the sender learns delivery without any tool call', async () => {
    // Re-establish contact after the unblock above, through the acceptProfiles rule this time.
    await alice.ownerOk('configure', { acceptProfiles: ['ace:text:1'] });
    await bob.client.callOk('ace_network', { action: 'connect', peer: alice.aceId });
    const workers = new AgentWorkers(stack.service.runtime, stack.service.vault, silent, { scanMs: 50, maintainMs: 200 });
    workers.start();
    try {
      await eventually(async () => stack.service.runtime.receivers.has(alice.aceId) && stack.service.runtime.receivers.has(bob.aceId));
      await eventually(async () => (await bob.client.callOk('ace_network', { action: 'peers' })).peers.find((p: { aceId: string; status: string }) => p.aceId === alice.aceId && p.status === 'admitted'));
      const sent = await bob.client.callOk('ace_send', { to: alice.aceId, type: 'ace:text:1', body: { message: 'via worker' } });
      const got = await alice.client.callOk('ace_inbox', { waitSeconds: 10, from: bob.aceId, type: 'ace:text:1' });
      expect(got.messages.map((m: { body: unknown }) => m.body)).toContainEqual({ message: 'via worker' });
      await eventually(async () => (await outboxStatus(bob, sent.messageId))?.status === 'delivered');
      expect(stack.relay.pending(alice.aceId)).toBe(0);
      expect(stack.relay.requests.filter((r) => r.path === '/v1/listen').every((r) => r.forwardedFor === null)).toBe(true);

      // A settings change restarts the receiver with the new policy.
      await alice.ownerOk('configure', { card: { description: 'Alice 2' } });
      await eventually(async () => stack.relay.cards.get(alice.aceId)!.card.card.description === 'Alice 2');
      await eventually(async () => stack.service.runtime.receivers.has(alice.aceId));

      // Delete stops the receiver, unregisters and erases everything.
      await bob.ownerOk('delete', { confirm: 'DELETE' });
      expect(stack.service.runtime.receivers.has(bob.aceId)).toBe(false);
      expect(stack.relay.kels.has(bob.aceId)).toBe(false);
      expect(await stack.service.vault.load(bob.aceId)).toBeNull();
      expect(await stack.redis.keys(`acemcp:*${bob.aceId}*`)).toEqual([]);
      await expect(bob.client.call('ace_identity')).rejects.toThrow(/valid client access token/); // the grant died with the identity
    } finally {
      await workers.stop();
    }
  });
});
