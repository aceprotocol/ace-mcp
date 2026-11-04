export type ToolOutcome = 'ok' | 'error';

/**
 * In-process Prometheus counters/gauges for `/metrics` (spec § 5.7). Tool names are constants, so labels need no escaping.
 * Every call is counted, argument errors included (the tools validate their own arguments).
 */
export class Telemetry {
  readonly #tools = new Map<string, number>();

  recordTool(tool: string, outcome: ToolOutcome): void {
    const k = `${tool}|${outcome}`;
    this.#tools.set(k, (this.#tools.get(k) ?? 0) + 1);
  }

  render(extra: { identities: number; receivers: number }): string {
    const lines = ['# TYPE ace_mcp_tool_calls_total counter'];
    for (const [k, v] of this.#tools) {
      const [tool, outcome] = k.split('|');
      lines.push(`ace_mcp_tool_calls_total{tool="${tool}",outcome="${outcome}"} ${v}`);
    }
    lines.push(
      '# TYPE ace_mcp_identities gauge', `ace_mcp_identities ${extra.identities}`,
      '# TYPE ace_mcp_receivers gauge', `ace_mcp_receivers ${extra.receivers}`,
    );
    return lines.join('\n') + '\n';
  }
}
