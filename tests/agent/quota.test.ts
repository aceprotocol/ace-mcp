import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { StoredMessage } from '@ace-protocol/sdk';
import { createStack, type Stack } from '../helpers/stack.js';
import { createIdentity, eventually, startListening, type HostedTestAgent } from '../helpers/client.js';
import { buildApp, type McpApp } from '../../src/app.js';
import { AgentWorkers } from '../../src/agent/workers.js';

let stack: Stack, url: string, alice: HostedTestAgent, bob: HostedTestAgent, capped: McpApp;
const silent = { error: () => undefined };
const BIG = 200_000; // characters per message (ace:text:1 allows 262 144)

beforeAll(async () => {
  stack = await createStack(50);
  url = await startListening(stack.service);
  alice = await createIdentity(stack.service, url);
  bob = await createIdentity(stack.service, url);
  // Contact through Alice's acceptProfiles rule, on the tool-call receive path.
  await alice.ownerOk('configure', { contact: 'open', listed: true, acceptProfiles: ['ace:text:1'] });
  await bob.client.callOk('ace_network', { action: 'connect', peer: alice.aceId });
  await alice.client.callOk('ace_inbox', {});
  await bob.client.callOk('ace_inbox', {});
  // A message counts twice at admission (Inbox journal + message log): Alice has room for two big messages, not three.
  const base = await stack.service.runtime.withIdentity(alice.aceId, undefined, (c) => c.store.bytes());
  capped = await buildApp({ config: { ...stack.config, maxStoreBytes: base + Math.floor(3.5 * BIG) }, redis: stack.redis, relayFetch: stack.relay.fetch });
});
afterAll(async () => {
  await alice?.client.close(); await bob?.client.close();
  await capped?.app.close();
  await stack?.close();
});

const log = (o: { unreadOnly?: boolean } = {}) => capped.runtime.withIdentity(alice.aceId, undefined, async (c) =>
  (await (await c.network()).messages!.list({ ...o, from: bob.aceId, limit: 100 })).map((m: StoredMessage) => ({ text: (m.body.message as string).slice(0, 2), read: m.read, messageId: m.messageId })));

describe('per-identity store byte cap', () => {
  it('leaves messages on the relay past the cap, evicts read messages oldest first, never unread ones', async () => {
    const workers = new AgentWorkers(capped.runtime, capped.vault, silent, { scanMs: 50, maintainMs: 100, fullRetryMs: 200 });
    workers.start();
    try {
      await eventually(async () => capped.runtime.receivers.has(alice.aceId));
      for (const n of ['m1', 'm2', 'm3']) await bob.client.callOk('ace_send', { to: alice.aceId, type: 'ace:text:1', body: { message: n + 'x'.repeat(BIG) } });
      await eventually(async () => (await log()).length === 2);
      await new Promise((r) => setTimeout(r, 500)); // several follow, restart and upkeep rounds
      expect((await log()).map((m) => m.text).sort()).toEqual(['m1', 'm2']); // unread messages are never evicted
      // m3 waits on the relay (receiver_capacity); Bob's Outbox may have queued retries of it beside it.
      expect(stack.relay.pending(alice.aceId)).toBeGreaterThanOrEqual(1);

      // Reading frees nothing until the messages are acknowledged; then the oldest read one is evicted for m3 (the
      // receiver stopped at back-pressure and restarts, which also drops the Inbox journal's copies).
      const [m1, m2] = await log(); // the two unread messages, in either order
      await capped.runtime.withIdentity(alice.aceId, undefined, async (c) => (await c.network()).messages!.ack([{ from: bob.aceId, messageId: m1.messageId }, { from: bob.aceId, messageId: m2.messageId }]));
      await eventually(async () => (await log()).some((m) => m.text === 'm3'));
      // Eviction has whole-second granularity (the log's retention cutoff): m2 goes too when it arrived in m1's second.
      const kept = (await log({ unreadOnly: false })).map((m) => m.text);
      expect(kept).toContain('m3');
      expect(kept).not.toContain('m1');
      await eventually(async () => stack.relay.pending(alice.aceId) === 0); // retries of m3 are acknowledged as duplicates
      const bytes = await capped.runtime.withIdentity(alice.aceId, undefined, (c) => c.store.bytes());
      expect(bytes).toBeLessThanOrEqual(capped.deps.config.maxStoreBytes + 2 * BIG);
    } finally {
      await workers.stop();
    }
  });

  it('refuses an outbound message that does not fit (the Outbox counts too)', async () => {
    const base = await stack.service.runtime.withIdentity(bob.aceId, undefined, (c) => c.store.bytes());
    const tight = await buildApp({ config: { ...stack.config, maxStoreBytes: base + Math.floor(BIG / 2) }, redis: stack.redis, relayFetch: stack.relay.fetch });
    try {
      const send = (message: string) => tight.runtime.withIdentity(bob.aceId, undefined, async (c) => (await c.network()).send(alice.aceId, 'ace:text:1', { message }));
      await expect(send('x'.repeat(BIG))).rejects.toMatchObject({ code: 'receiver_capacity' });
      expect(await tight.runtime.withIdentity(bob.aceId, undefined, (c) => c.store.bytes())).toBe(base); // nothing stored
      await expect(send('small')).resolves.toMatchObject({ to: alice.aceId });
    } finally {
      await tight.app.close();
    }
  });
});
