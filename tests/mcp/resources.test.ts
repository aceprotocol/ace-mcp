import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BUNDLED_MANIFESTS, profileDigest } from '@ace-protocol/sdk';
import { createStack, type Stack } from '../helpers/stack.js';
import { createIdentity, startListening, toolCount, type HostedTestAgent } from '../helpers/client.js';

let stack: Stack, url: string, agent: HostedTestAgent;
beforeAll(async () => { stack = await createStack(38); url = await startListening(stack.service); agent = await createIdentity(stack.service, url); });
afterAll(async () => { await agent?.client.close(); await stack?.close(); });

describe('resources', () => {
  it('serves ace://guide and ace://profiles derived from the SDK bundled manifests', async () => {
    const { client } = agent.client;
    const list = await client.listResources();
    expect(Object.fromEntries(list.resources.map((r) => [r.uri, r.mimeType]))).toEqual({ 'ace://guide': 'text/markdown', 'ace://profiles': 'application/json' });
    const text = ((await client.readResource({ uri: 'ace://guide' })).contents[0] as { text: string }).text;
    for (const s of ['hosted', 'ace_network', 'ace_send', 'ace_inbox', 'receipt', 'stablecoin', 'owner credential', 'can read']) expect(text.toLowerCase()).toContain(s.toLowerCase());
    for (const gone of ['SoulPass', 'intent', 'link_', 'MLS', 'recommended']) expect(text).not.toContain(gone);
    expect(text).not.toMatch(/test-|staging|localhost/);
    const profiles = JSON.parse(((await client.readResource({ uri: 'ace://profiles' })).contents[0] as { text: string }).text);
    expect(profiles.map((p: { id: string; digest: string }) => [p.id, p.digest])).toEqual(Object.values(BUNDLED_MANIFESTS).map((m) => [m.id, profileDigest(m)]));
    expect(profiles.find((p: { id: string }) => p.id === 'ace:commerce:1').messages).toHaveLength(8);
    expect(client.getServerVersion()).toMatchObject({ name: 'ace-mcp', version: JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version });
  });

  it('counts tool calls by outcome (telemetry)', async () => {
    const t = stack.service.telemetry;
    const before = toolCount(t, 'ace_network', 'ok');
    expect((await agent.client.call('ace_network', { action: 'discover' })).ok).toBe(true);
    expect((await agent.client.call('ace_send', { to: 'ace:sha256:' + 'a'.repeat(64), type: 'example:unknown:1', body: {} })).ok).toBe(false);
    expect(toolCount(t, 'ace_network', 'ok')).toBe(before + 1);
    expect(toolCount(t, 'ace_send', 'error')).toBeGreaterThanOrEqual(1);
  });
});
