import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createStack, type Stack } from '../helpers/stack.js';
import { createIdentity, eventually, startListening } from '../helpers/client.js';
import { AgentRuntime } from '../../src/agent/runtime.js';
import { AgentWorkers } from '../../src/agent/workers.js';
import { defaultSettings } from '../../src/agent/settings.js';
import { IDENTITY_PREFIX } from '../../src/store/keyspace.js';
import { ACEError, RelayClient, SoftwareIdentity } from '@ace-protocol/sdk';
import { RELAY } from '../helpers/fake-relay.js';
import type { HostedTestAgent } from '../helpers/client.js';

let stack: Stack, url: string;
const silent = { error: () => undefined };
const deleting = async (aceId: string) => await stack.redis.hexists(IDENTITY_PREFIX + aceId, 'deleting') === 1;
const settle = (p: Promise<unknown>) => p.then(() => 'ok', (e: unknown) => e);

beforeAll(async () => { stack = await createStack(48); url = await startListening(stack.service); });
afterAll(async () => { await stack?.close(); });

/** Another MCP replica: its own runtime and workers over the same Redis and relay. */
function replica(): { runtime: AgentRuntime; workers: AgentWorkers } {
  const runtime = new AgentRuntime({ redis: stack.redis, vault: stack.service.vault, config: stack.config, fetch: stack.relay.fetch, logger: silent });
  return { runtime, workers: new AgentWorkers(runtime, stack.service.vault, silent, { scanMs: 50, maintainMs: 100 }) };
}

/** What `ace init --import` does with the owner's export: re-key it (rotate twice, delegate) and register the new KEL. */
async function importElsewhere(a: HostedTestAgent): Promise<void> {
  const { importInstructions: _, ...data } = await a.ownerOk('export', { confirm: 'EXPORT' });
  const id = SoftwareIdentity.fromExport(data);
  await id.rotate(); await id.rotate(); await id.delegate();
  await new RelayClient(RELAY, { fetch: stack.relay.fetch }).register(id);
}

describe('identity deletion', () => {
  it('a tool call in flight during delete cannot re-register, publish or write after the unregister; new calls are refused', async () => {
    const a = await createIdentity(stack.service, url, 'Racer');
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let entered!: () => void;
    const inside = new Promise<void>((r) => { entered = r; });
    const attempts: unknown[] = [];
    const call = stack.service.runtime.withIdentity(a.aceId, '127.0.0.1', async (c) => {
      entered();
      await gate;
      attempts.push(await settle(c.relay.register(c.identity)));
      attempts.push(await settle(c.updateSettings(() => defaultSettings('Revived'))));
      attempts.push(await settle(c.store.write('late.json', new Uint8Array([1]))));
    });
    await inside;
    const del = a.owner('delete', { confirm: 'DELETE' });
    await eventually(() => deleting(a.aceId));
    // Calls that start during the deletion fail unauthenticated (MCP and owner surfaces alike).
    await expect(a.client.call('ace_identity')).rejects.toThrow(/valid client access token/);
    await expect(stack.service.runtime.withIdentity(a.aceId, undefined, async () => 'ran')).rejects.toMatchObject({ code: 'unauthenticated' });
    expect(await a.owner('export', { confirm: 'EXPORT' })).toMatchObject({ ok: false, error: 'owner_credential_required' });
    expect(stack.relay.requests.some((r) => r.path === '/v1/unregister')).toBe(false); // waiting for the in-flight call
    const before = stack.relay.requests.length;
    release();
    await call;
    expect(attempts.every((x) => x instanceof Error)).toBe(true);
    expect(stack.relay.requests.slice(before).map((r) => r.path)).not.toContain('/v1/register');
    expect((await del).ok).toBe(true);
    expect(stack.relay.kels.has(a.aceId)).toBe(false);
    expect(stack.relay.descriptors.has(a.aceId)).toBe(false);
    expect(await stack.redis.keys(`acemcp:*${a.aceId}*`)).toEqual([]);
    await a.client.close();
  });

  it('another replica does not restart the receiver of an identity being deleted, and does not re-register it', async () => {
    const a = await createIdentity(stack.service, url, 'Replicated');
    const other = replica();
    other.workers.start();
    try {
      await eventually(async () => other.runtime.receivers.has(a.aceId));
      // The marker alone stops the remote receiver and keeps scans from restarting it.
      await stack.service.vault.beginDelete(a.aceId);
      await eventually(async () => !other.runtime.receivers.has(a.aceId));
      const listens = stack.relay.requests.filter((r) => r.path === '/v1/listen').length;
      await new Promise((r) => setTimeout(r, 500)); // several scan and upkeep intervals
      expect(other.runtime.receivers.has(a.aceId)).toBe(false);
      expect(stack.relay.requests.filter((r) => r.path === '/v1/listen').length).toBe(listens);

      // Resuming restarts it; then a real delete (this process has no workers) leaves the replica unable to re-register.
      await stack.service.vault.cancelDelete(a.aceId);
      await eventually(async () => other.runtime.receivers.has(a.aceId));
      await a.ownerOk('delete', { confirm: 'DELETE' });
      await eventually(async () => !other.runtime.receivers.has(a.aceId));
      await new Promise((r) => setTimeout(r, 500));
      expect(stack.relay.kels.has(a.aceId)).toBe(false);
      expect(await stack.redis.keys(`acemcp:*${a.aceId}*`)).toEqual([]);
    } finally {
      await other.workers.stop();
      await a.client.close();
    }
  });

  it('a failed unregister clears the marker: the identity, its auth and its receivers resume in every process', async () => {
    const a = await createIdentity(stack.service, url, 'Survivor');
    const route = stack.relay.route.bind(stack.relay);
    stack.relay.route = async (method, u, headers, body) => {
      if (u.pathname === '/v1/unregister') throw new Error('relay down');
      return route(method, u, headers, body);
    };
    const other = replica();
    try {
      expect(await a.owner('delete', { confirm: 'DELETE' })).toMatchObject({ ok: false });
      expect(await deleting(a.aceId)).toBe(false);
      expect(await stack.service.vault.exists(a.aceId)).toBe(true);
      expect(await stack.service.vault.listIdentities()).toContain(a.aceId);
      expect((await a.client.callOk('ace_identity')).aceId).toBe(a.aceId);
      expect(stack.relay.kels.has(a.aceId)).toBe(true);
      other.workers.start();
      await eventually(async () => other.runtime.receivers.has(a.aceId));
    } finally {
      stack.relay.route = route;
      await other.workers.stop();
      await a.client.close();
    }
  });

  it('delete succeeds when relay answers stale_seq (the identity was imported and re-keyed elsewhere)', async () => {
    const a = await createIdentity(stack.service, url, 'Imported');
    await importElsewhere(a);
    expect(await a.ownerOk('delete', { confirm: 'DELETE' })).toMatchObject({ ok: true, aceId: a.aceId });
    expect(stack.relay.kels.get(a.aceId)?.seq).toBeGreaterThan(1); // the new custodian's registration stays
    expect(await stack.redis.keys(`acemcp:*${a.aceId}*`)).toEqual([]);
    await a.client.close();
  });

  it.each(['kel_conflict', 'identity_conflict'])('delete treats %s from unregister as a registration no longer ours', async (relayCode) => {
    const a = await createIdentity(stack.service, url, 'Conflicted');
    const route = stack.relay.route.bind(stack.relay);
    stack.relay.route = async (method, u, headers, body) => {
      if (u.pathname === '/v1/unregister') throw new ACEError(relayCode as never, 'conflict');
      return route(method, u, headers, body);
    };
    try {
      expect((await a.owner('delete', { confirm: 'DELETE' })).ok).toBe(true);
      expect(await stack.redis.keys(`acemcp:*${a.aceId}*`)).toEqual([]);
    } finally {
      stack.relay.route = route;
      await a.client.close();
    }
  });

  it('a receiver that meets stale_seq stops and marks the identity superseded; scans do not restart it', async () => {
    const a = await createIdentity(stack.service, url, 'Superseded');
    const other = replica();
    other.workers.start();
    try {
      await eventually(async () => other.runtime.receivers.has(a.aceId));
      await importElsewhere(a);
      await eventually(async () => !other.runtime.receivers.has(a.aceId));
      expect(await stack.redis.hexists(IDENTITY_PREFIX + a.aceId, 'supersededAt')).toBe(1);
      expect(await stack.service.vault.listIdentities()).not.toContain(a.aceId);
      const listens = stack.relay.requests.filter((r) => r.path === '/v1/listen').length;
      await new Promise((r) => setTimeout(r, 500)); // several scan and upkeep intervals
      expect(other.runtime.receivers.has(a.aceId)).toBe(false);
      expect(stack.relay.requests.filter((r) => r.path === '/v1/listen').length).toBe(listens);
      expect((await a.client.callOk('ace_identity')).supersededAt).toEqual(expect.any(Number));
      expect((await a.ownerOk('delete', { confirm: 'DELETE' })).ok).toBe(true);
    } finally {
      await other.workers.stop();
      await a.client.close();
    }
  });

  it('a receiver whose superseded mark fails (Redis error) still stops, logs it and leaves no unhandled rejection', async () => {
    const a = await createIdentity(stack.service, url, 'MarkFails');
    const logged: string[] = [];
    const runtime = new AgentRuntime({ redis: stack.redis, vault: stack.service.vault, config: stack.config, fetch: stack.relay.fetch, logger: silent });
    const workers = new AgentWorkers(runtime, stack.service.vault, { error: (_o, msg) => { logged.push(msg); } }, { scanMs: 50, maintainMs: 100 });
    const mark = vi.spyOn(stack.service.vault, 'markSuperseded').mockRejectedValue(new Error('redis down'));
    const unhandled: unknown[] = [];
    const onUnhandled = (e: unknown) => { unhandled.push(e); };
    process.on('unhandledRejection', onUnhandled);
    workers.start();
    try {
      await eventually(async () => runtime.receivers.has(a.aceId));
      await importElsewhere(a);
      await eventually(async () => logged.includes('could not mark the identity superseded; receiver stopped'));
      await eventually(async () => !runtime.receivers.has(a.aceId));
      expect(mark).toHaveBeenCalled();
      await new Promise((r) => setTimeout(r, 100));
      expect(unhandled).toEqual([]);
    } finally {
      await workers.stop();
      mark.mockRestore();
      process.off('unhandledRejection', onUnhandled);
      await a.client.close();
    }
  });
});
