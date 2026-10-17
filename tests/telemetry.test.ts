import { describe, expect, it } from 'vitest';
import { Telemetry } from '../src/telemetry.js';
import { toolCount } from './helpers/client.js';

describe('Telemetry', () => {
  it('counts tool calls by tool and outcome and renders Prometheus text', () => {
    const t = new Telemetry();
    t.recordTool('ace_send', 'ok');
    t.recordTool('ace_send', 'ok');
    t.recordTool('ace_send', 'error');
    expect(toolCount(t, 'ace_send', 'ok')).toBe(2);
    expect(toolCount(t, 'ace_send', 'error')).toBe(1);
    expect(toolCount(t, 'ace_inbox', 'ok')).toBe(0);
    const text = t.render({ identities: 4, receivers: 0 });
    expect(text).toContain('# TYPE ace_mcp_tool_calls_total counter\n');
    expect(text).toContain('ace_mcp_tool_calls_total{tool="ace_send",outcome="ok"} 2\n');
    expect(text).toContain('ace_mcp_tool_calls_total{tool="ace_send",outcome="error"} 1\n');
    expect(text).toContain('# TYPE ace_mcp_identities gauge\nace_mcp_identities 4\n');
  });
});
