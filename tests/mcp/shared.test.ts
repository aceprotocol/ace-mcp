import { describe, expect, it } from 'vitest';
import { ACEError } from '@ace-protocol/sdk';
import { McpToolError } from '../../src/errors.js';
import { ok, run } from '../../src/mcp/tools/shared.js';
import { Telemetry } from '../../src/telemetry.js';
import { toolCount } from '../helpers/client.js';

describe('run', () => {
  it('logs internal errors (only) and returns the mapped error result', async () => {
    const logged: unknown[] = [];
    const deps = { logger: { error: (obj: object) => { logged.push(obj); } }, telemetry: new Telemetry() };
    const r1 = await run(deps, 't', async () => { throw new Error('boom'); });
    expect(r1).toMatchObject({ isError: true, structuredContent: { error: 'internal', message: 'internal error', retryable: false } });
    expect(logged).toHaveLength(1);
    await run(deps, 't', async () => { throw new ACEError('unknown_peer', 'gone'); });
    await run(deps, 't', async () => { throw new McpToolError('rate_limited', 'slow down', true); });
    expect(logged).toHaveLength(1);
  });

  it('records each call as ok or error under the tool name', async () => {
    const telemetry = new Telemetry();
    const deps = { logger: { error: () => undefined }, telemetry };
    await run(deps, 'ace_a', async () => ok({}));
    await run(deps, 'ace_a', async () => ok({}));
    await run(deps, 'ace_a', async () => { throw new McpToolError('invalid_argument', 'no', false); });
    await run(deps, 'ace_b', async () => { throw new Error('boom'); });
    expect(toolCount(telemetry, 'ace_a', 'ok')).toBe(2);
    expect(toolCount(telemetry, 'ace_a', 'error')).toBe(1);
    expect(toolCount(telemetry, 'ace_b', 'error')).toBe(1);
  });
});
