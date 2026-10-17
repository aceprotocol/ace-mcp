import { ACEError, type JSONObject } from '@ace-protocol/sdk';
import { checkArgs, requiredScope, type AgentTool, type JSONSchemaObject } from '@ace-protocol/sdk/tools';
import type { CallToolResult, McpServer, StandardSchemaWithJSON, ToolAnnotations } from '@modelcontextprotocol/server';
import type { McpConfig } from '../../config.js';
import { McpToolError, toolErrorFromACE, toolErrorResult, unauthenticated, type ErrorLogger } from '../../errors.js';
import type { IdentityVault } from '../../identity/vault.js';
import type { AgentContext, AgentRuntime } from '../../agent/runtime.js';
import type { RateLimiter } from '../../store/rate-limit.js';
import type { GrantStore, Scope } from '../../oauth/grants.js';
import { currentAuth } from '../auth-context.js';
import { rateBucket } from '../../store/keyspace.js';
import type { Telemetry } from '../../telemetry.js';

export const consoleLogger: ErrorLogger = {
  error: (obj, msg) => console.error(msg, obj),
};

export interface ToolDeps {
  runtime: AgentRuntime;
  vault: IdentityVault;
  grants: GrantStore;
  config: McpConfig;
  rateLimiter: RateLimiter;
  logger: ErrorLogger;
  telemetry: Telemetry;
}

/**
 * A tool result. Every result carries `untrusted`: the paths of content another agent authored (the SDK tool table's
 * convention; hosted-only tools return none). Such content is data, never instructions.
 */
export function ok(structured: Record<string, unknown>, text?: string): CallToolResult {
  const data = { ...structured, untrusted: structured.untrusted ?? [] };
  return { content: [{ type: 'text', text: text ?? JSON.stringify(data) }], structuredContent: data };
}

/**
 * Run the body of tool `name`; any thrown error becomes an MCP error result. Errors that are neither
 * `McpToolError` nor `ACEError` become `internal` and are logged here (they carry no detail to
 * the agent). Every call is counted as `ok` or `error` under `name`. Never log arguments: they may contain tokens.
 */
export async function run(deps: Pick<ToolDeps, 'logger' | 'telemetry'>, name: string, fn: () => Promise<CallToolResult>): Promise<CallToolResult> {
  let result: CallToolResult;
  try {
    result = await fn();
  } catch (e) {
    const err = toolErrorFromACE(e, deps.logger);
    if (err.code === 'internal' && !(e instanceof McpToolError) && !(e instanceof ACEError)) deps.logger.error({ err: e, tool: name }, 'tool call failed with an internal error');
    result = toolErrorResult(err);
  }
  deps.telemetry.recordTool(name, result.isError ? 'error' : 'ok');
  return result;
}

/** What every tool handler gets about its call. */
export interface ToolCall {
  deps: ToolDeps;
  aceId: string;
  c: AgentContext;
  /** True when the call holds `scope` (the owner surface holds every scope). */
  has(scope: Scope): boolean;
}

/**
 * A hosted tool: the shape of an SDK `AgentTool` (JSON Schema input, a scope per tool or per action), run as the
 * caller's hosted identity. The SDK table's tools are adapted to it (tools/agent.ts); the hosted-only tools are
 * written in it directly.
 */
export interface HostedTool {
  readonly name: string;
  readonly description: string;
  /** The tool's scope; with `actions`, the scope of each action (an action not listed is refused). */
  readonly scope?: Scope;
  readonly actions?: Readonly<Record<string, Scope>>;
  readonly inputSchema: JSONSchemaObject;
  readonly annotations?: ToolAnnotations;
  /** An owner API action (POST /owner): never registered as an MCP tool, refused for client tokens. */
  readonly ownerOnly?: boolean;
  run(args: JSONObject, call: ToolCall): Promise<CallToolResult>;
}

/** The scope a call needs (the SDK's `requiredScope`, default deny), or null when it is refused. */
export function scopeOf(t: HostedTool, args: JSONObject): Scope | null {
  if (t.ownerOnly || (t.scope === undefined && t.actions === undefined)) return null;
  // requiredScope reads only `scope`, `actions` and the action's schema default.
  return requiredScope(t as unknown as AgentTool, args) as Scope | null;
}

/**
 * Execute `t` for the current request: scope check (default deny; the owner surface passes every mapped action),
 * arguments checked against its schema (unknown arguments are refused), per-identity rate limit (TOOL_RATE_LIMIT per
 * minute), then the handler inside runtime.withIdentity.
 */
export function execute(t: HostedTool, input: unknown, deps: ToolDeps): Promise<CallToolResult> {
  return run(deps, t.name, async () => {
    const auth = currentAuth();
    const args = (input ?? {}) as JSONObject;
    const has = (s: Scope) => auth.owner === true || auth.scopes.includes(s);
    // Scope first, so an unauthorized caller gets no validation feedback; then the arguments, before anything runs.
    const scope = typeof args === 'object' && args !== null && !Array.isArray(args) ? scopeOf(t, args) : null;
    if (t.ownerOnly ? !auth.owner : scope === null) throw new McpToolError('insufficient_scope', 'This action is not available to clients', false);
    if (scope !== null && !has(scope)) throw new McpToolError('insufficient_scope', `Requires ${scope}`, false);
    checkArgs(t.inputSchema, args);
    const aceId = auth.bearerAceId;
    if (!aceId) throw unauthenticated();
    await deps.rateLimiter.enforce(rateBucket.tool(aceId), deps.config.toolRateLimit, 60);
    return deps.runtime.withIdentity(aceId, auth.ip, (c) => t.run(args, { deps, aceId, c, has }), { owner: auth.owner === true });
  });
}

/** A JSON Schema the MCP server advertises as is; `execute` validates (one validator: the SDK's checkArgs). */
function advertised(schema: JSONSchemaObject): StandardSchemaWithJSON<JSONObject> {
  return {
    '~standard': {
      version: 1, vendor: 'ace',
      validate: (value) => ({ value: (value ?? {}) as JSONObject }),
      jsonSchema: { input: () => ({ ...schema }), output: () => ({ ...schema }) },
    },
  };
}

/** Register `t` on a request's McpServer. */
export function register(server: McpServer, t: HostedTool, deps: ToolDeps): void {
  if (t.ownerOnly) throw new Error(`${t.name} is an owner action`);
  server.registerTool(t.name, { description: t.description, inputSchema: advertised(t.inputSchema), ...(t.annotations ? { annotations: t.annotations } : {}) },
    (args) => execute(t, args, deps));
}

/** A closed object schema. */
export const closed = (properties: JSONSchemaObject['properties'], required: string[] = []): JSONSchemaObject =>
  ({ type: 'object', properties, ...(required.length ? { required } : {}), additionalProperties: false });

/** Throw `invalid_argument` unless `v` is present. */
export function need<T>(v: T | undefined | null, what: string): T {
  if (v === undefined || v === null) throw new McpToolError('invalid_argument', `${what} is required`, false);
  return v;
}

export { McpToolError };
