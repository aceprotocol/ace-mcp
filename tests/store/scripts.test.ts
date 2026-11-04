import { describe, expect, it } from 'vitest';
import type { Redis } from 'ioredis';
import { luaScript, runScript } from '../../src/store/scripts.js';

/** A stand-in for ioredis' defineCommand: records definitions and calls. */
function fakeClient(defined: string[], calls: unknown[][]): Redis {
  const c: Record<string, unknown> = {};
  c.defineCommand = (name: string, def: { numberOfKeys: number; lua: string }) => {
    defined.push(`${name}/${def.numberOfKeys}`);
    c[name] = async (...args: unknown[]) => { calls.push(args); return 1; };
  };
  return c as unknown as Redis;
}

describe('runScript', () => {
  it('defines each script once per client and passes KEYS then ARGV', async () => {
    const defined: string[] = [];
    const calls: unknown[][] = [];
    const r = fakeClient(defined, calls);
    const a = luaScript('a', 1, 'return 1');
    const b = luaScript('b', 2, 'return 2');
    expect(await runScript(r, a, 'k', 'v')).toBe(1);
    await runScript(r, a, 'k2');
    await runScript(r, b, 'k1', 'k2', 'v');
    expect(defined).toEqual(['acemcp_a/1', 'acemcp_b/2']);
    expect(calls).toEqual([['k', 'v'], ['k2'], ['k1', 'k2', 'v']]);
    await runScript(fakeClient(defined, calls), a, 'k');
    expect(defined).toEqual(['acemcp_a/1', 'acemcp_b/2', 'acemcp_a/1']); // another client defines its own
  });
});
