import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createStack, type Stack } from '../helpers/stack.js';
import { createIdentity, eventually, startListening, type HostedTestAgent } from '../helpers/client.js';
import { AgentWorkers } from '../../src/agent/workers.js';

let stack: Stack, url: string, alice: HostedTestAgent, carol: HostedTestAgent;
const silent = { error: () => undefined };

beforeAll(async () => {
  stack = await createStack(52);
  url = await startListening(stack.service);
  alice = await createIdentity(stack.service, url, 'Alice');
  carol = await createIdentity(stack.service, url, 'Carol');
});
afterAll(async () => {
  await alice?.client.close(); await carol?.client.close();
  await stack?.close();
});

describe('a settings change and the resident receiver', () => {
  it('no contact request is auto-accepted under the old policy once configure returns', async () => {
    await alice.ownerOk('configure', { visibility: 'public', acceptProfiles: ['ace:text:1'] });
    // Long upkeep: the receiver's own periodic settings check cannot be what restarts it.
    const workers = new AgentWorkers(stack.service.runtime, stack.service.vault, silent, { scanMs: 50, maintainMs: 60_000 });
    workers.start();
    try {
      await eventually(async () => stack.service.runtime.receivers.has(alice.aceId));
      await alice.ownerOk('configure', { acceptProfiles: [] });
      // A stranger's request right after configure returns: held for an explicit accept, not admitted.
      await carol.client.callOk('ace_network', { action: 'connect', peer: alice.aceId });
      const { requests } = await eventually(async () => {
        const r = await alice.client.callOk('ace_network', { action: 'requests' });
        return r.requests.length ? r : undefined;
      });
      expect(requests).toMatchObject([{ from: carol.aceId }]);
      expect((await alice.client.callOk('ace_network', { action: 'peers' })).peers).toEqual([]);
    } finally {
      await workers.stop();
    }
  });
});
