import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createStack, type Stack } from '../helpers/stack.js';
import { provisionIdentity } from '../../src/identity/provision.js';
import { deriveSubkey, kekCipher, SealedDataError } from '../../src/identity/kek.js';
import { identityKeys } from '../../src/store/keyspace.js';
import { prekeyProtector } from '../../src/agent/runtime.js';
import { loadSettings } from '../../src/agent/settings.js';

let stack: Stack;
beforeAll(async () => { stack = await createStack(33); });
afterAll(() => stack?.close());

describe('prekey seeds are protected like identity seeds', () => {
  it('the vault document is sealed under the prekey subkey inside the store layer', async () => {
    const { identity } = await provisionIdentity(stack.service.deps, '127.0.0.1');
    const aceId = identity.getACEId();
    const raw = await stack.redis.getBuffer(identityKeys(aceId).storeValues + 'prekeys.json');
    expect(raw).not.toBeNull();
    // The store layer alone (store subkey) yields only another sealed blob, never the seed document.
    const storeLayer = kekCipher(deriveSubkey(stack.config.kek, 'store', aceId)).open(`store\0${aceId}\0prekeys.json`, raw!);
    expect(() => JSON.parse(storeLayer.toString('utf8'))).toThrow();
    expect(storeLayer.toString('latin1')).not.toContain('"seed"');
    // The prekey subkey opens it; the current prekey is the one the published descriptor carries.
    const doc = JSON.parse(new TextDecoder().decode(await prekeyProtector(stack.config.kek, aceId).open(storeLayer)));
    expect(doc).toMatchObject({ version: 2, current: { id: stack.relay.descriptors.get(aceId)!.descriptor.prekey.id } });
    // Bound to its identity: another identity's subkey cannot open it.
    await expect(prekeyProtector(stack.config.kek, 'ace:sha256:' + '0'.repeat(64)).open(storeLayer)).rejects.toBeInstanceOf(SealedDataError);
    // Settings are saved for the worker.
    expect((await stack.service.runtime.withIdentity(aceId, undefined, (c) => loadSettings(c.store)))?.card).toEqual({ tags: ['hosted'] });
  });
});

describe('send-side client', () => {
  it('opens beside a receiver: no receive lock, no inbox writes', async () => {
    const { identity } = await provisionIdentity(stack.service.deps, '127.0.0.1');
    const aceId = identity.getACEId();
    await stack.service.runtime.withIdentity(aceId, undefined, async (c) => {
      const held = await c.store.lock('receive', { timeoutMs: 0 }); // as the resident worker would
      try {
        const before = await c.store.list('inbox/');
        const client = await c.network();
        await client.publish();
        expect(() => client.inbox).toThrow(/receive role/);
        expect(await c.store.list('inbox/')).toEqual(before);
      } finally {
        await held();
      }
    });
  });
});
