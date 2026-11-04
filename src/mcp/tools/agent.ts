import { ACEError, type JSONObject } from '@ace-protocol/sdk';
import { AGENT_TOOLS, type AgentTool } from '@ace-protocol/sdk/tools';
import type { CallToolResult } from '@modelcontextprotocol/server';
import { toolErrorFromACE } from '../../errors.js';
import { ok, type HostedTool, type ToolCall } from './shared.js';
import type { Scope } from '../../oauth/grants.js';
import { liveDelegations, publishedProfiles } from '../../agent/settings.js';
import { nowSeconds } from '../../clock.js';

/** The SDK's result of `t` as a hosted result, with `extra` members merged in. */
async function runAgentTool(t: AgentTool, args: JSONObject, call: ToolCall, extra: Record<string, unknown> = {}): Promise<CallToolResult> {
  const { data } = await t.run(await call.c.network(), args);
  return ok({ ...(data as Record<string, unknown>), ...extra });
}

/**
 * Hosted facts beside the SDK's `ace_identity`: custody, vault timestamps, the descriptor `ext` as published (with the
 * `ace:delegation:1` credentials), those credentials' issuers and the card record's ERC-8004 bindings.
 */
function identityExtra({ c }: ToolCall): Record<string, unknown> {
  const s = c.settings, r = c.record;
  const now = nowSeconds(), { ext } = publishedProfiles(s, now);
  return {
    custody: 'hosted', createdAt: r.createdAt, lastUsedAt: r.lastUsedAt,
    ...(r.exportedAt ? { exportedAt: r.exportedAt } : {}), ...(r.supersededAt ? { supersededAt: r.supersededAt } : {}),
    ...(ext ? { ext } : {}),
    delegations: liveDelegations(s, now).map((d) => ({ issuer: d.issuer, expiresAt: d.expiresAt })),
    erc8004: s.erc8004,
  };
}

/**
 * Before `ace_inbox read`: one inbox pull when no receiver runs in this process (the resident worker normally owns the
 * inbox and fills the message log). A receiver in another process holds `receive` (`lock_busy`): then the stored log
 * is all there is. A failed pull is reported beside the messages, never instead of them.
 */
async function inboxPull(args: JSONObject, { deps, aceId, c }: ToolCall): Promise<Record<string, unknown>> {
  if ((args.action ?? 'read') !== 'read' || deps.runtime.receivers.has(aceId)) return {};
  try {
    await (await c.receiver()).pull();
    return {};
  } catch (e) {
    if (e instanceof ACEError && e.code === 'lock_busy') return {};
    const err = toolErrorFromACE(e, deps.logger);
    return { pullError: { code: err.code, message: err.message, retryable: err.retryable } };
  }
}

const HOSTED_NOTE: Record<string, string> = {
  ace_inbox: ' Here, read first pulls the relay once when no resident receiver runs in this replica; waitSeconds then waits for the resident receiver to store new messages.',
  ace_identity: ' Custody is "hosted": this service holds your keys and can read your messages. Also: your descriptor ext as published (ace:delegation:1 credentials included), the issuers of those credentials, the ERC-8004 bindings of your card record, and supersededAt when the relay holds a newer key event log (the identity was imported elsewhere).',
};

function adapt(t: AgentTool): HostedTool {
  return {
    name: t.name, description: t.description + (HOSTED_NOTE[t.name] ?? ''),
    scope: t.scope as Scope, ...(t.actions ? { actions: t.actions as Readonly<Record<string, Scope>> } : {}),
    inputSchema: t.inputSchema,
    annotations: t.actions === undefined && t.scope === 'ace:read' ? { readOnlyHint: true } : { readOnlyHint: false, openWorldHint: true },
    // `execute` has checked the scope and the arguments, so an invalid call never pulls; the pull runs before the SDK
    // tool reads the log.
    run: async (args, call) => runAgentTool(t, args, call,
      t.name === 'ace_identity' ? identityExtra(call) : t.name === 'ace_inbox' ? await inboxPull(args, call) : {}),
  };
}

/** The SDK agent tool table (`@ace-protocol/sdk/tools`), served as hosted tools: the same names and semantics. */
export const agentTools: HostedTool[] = AGENT_TOOLS.map(adapt);
