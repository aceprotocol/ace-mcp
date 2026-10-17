import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import type { McpApp } from '../../src/app.js';
import type { Telemetry } from '../../src/telemetry.js';
import { sha256Hex } from '@ace-protocol/sdk';
import { provisionIdentity } from '../../src/identity/provision.js';
import { SCOPES, type Scope } from '../../src/oauth/grants.js';

type Result<T> = { ok: true; data: T } | { ok: false; error: string; message: string; retryable: boolean };

export interface McpTestClient {
  client: Client;
  call<T = Record<string, unknown>>(name: string, args?: Record<string, unknown>): Promise<Result<T>>;
  /** `call`, throwing `<error>: <message>` on a tool error. */
  callOk<T = any>(name: string, args?: Record<string, unknown>): Promise<T>;
  close(): Promise<void>;
}

export interface HostedTestAgent {
  client: McpTestClient;
  aceId: string;
  token: string;
  accessToken: string;
  owner<T = any>(action: string, args?: Record<string, unknown>): Promise<Result<T>>;
  ownerOk<T = any>(action: string, args?: Record<string, unknown>): Promise<T>;
}

export async function startListening(service: McpApp): Promise<string> {
  return (await service.app.listen({ host: '127.0.0.1', port: 0 })) + '/mcp';
}

/** An MCP client over HTTP with a client access token. */
export async function connect(url: string, accessToken: string): Promise<McpTestClient> {
  const transport = new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { authorization: `Bearer ${accessToken}` } } });
  const client = new Client({ name: 'ace-mcp-test', version: '0.0.0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
  await client.connect(transport);
  const call: McpTestClient['call'] = async (name, args = {}) => {
    const r = await client.callTool({ name, arguments: args }) as { isError?: boolean; structuredContent?: Record<string, unknown> };
    if (r.isError) return { ok: false, ...(r.structuredContent as { error: string; message: string; retryable: boolean }) };
    return { ok: true, data: r.structuredContent as never };
  };
  return {
    client, call,
    async callOk(name, args = {}) {
      const r = await call(name, args);
      if (!r.ok) throw new Error(`${name}: ${r.error}: ${r.message}`);
      return r.data as never;
    },
    close: () => transport.close(),
  };
}

/** Provision a hosted identity through the real flow (vault, settings, relay registration, descriptor) and grant a client. */
export async function createIdentity(service: McpApp, url: string, name: string, scopes: readonly Scope[] = SCOPES): Promise<HostedTestAgent> {
  const made = await provisionIdentity(service.deps, { name }, '127.0.0.1');
  const aceId = made.identity.getACEId();
  const tokens = await service.grants.create({ aceId, ownerHash: sha256Hex(made.token), clientId: 'test-client', resource: url, scopes: [...scopes] });
  const client = await connect(url, tokens.access_token);
  const owner = async <T>(action: string, args: Record<string, unknown> = {}): Promise<Result<T>> => {
    const r = await service.app.inject({ method: 'POST', url: '/owner', headers: { host: new URL(url).host, authorization: `Bearer ${made.token}` }, payload: { action, args } });
    const v = r.json();
    if (r.statusCode >= 400) return { ok: false, error: v.error, message: v.message ?? v.error, retryable: false };
    if (v.isError) return { ok: false, ...v.structuredContent };
    return { ok: true, data: (v.structuredContent ?? v) as T };
  };
  return {
    client, aceId, token: made.token, accessToken: tokens.access_token, owner,
    async ownerOk(action, args = {}) {
      const r = await owner(action, args);
      if (!r.ok) throw new Error(`${action}: ${r.error}: ${r.message}`);
      return r.data as never;
    },
  };
}

/** The `ace_mcp_tool_calls_total` counter for one tool and outcome, read from the rendered metrics. */
export function toolCount(t: Telemetry, tool: string, outcome: 'ok' | 'error'): number {
  const line = t.render({ identities: 0, receivers: 0 }).split('\n').find((l) => l.startsWith(`ace_mcp_tool_calls_total{tool="${tool}",outcome="${outcome}"} `));
  return line ? Number(line.slice(line.lastIndexOf(' ') + 1)) : 0;
}

/** Poll `fn` until it returns a truthy value (or throw after `ms`). */
export async function eventually<T>(fn: () => Promise<T | undefined | null | false>, ms = 15_000): Promise<T> {
  const deadline = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error('condition not reached');
    await new Promise((r) => setTimeout(r, 100));
  }
}
