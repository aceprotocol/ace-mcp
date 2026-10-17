import type { Redis } from 'ioredis';

/** A Lua script run through `redis.defineCommand` (EVALSHA, falling back to EVAL on NOSCRIPT). */
export interface LuaScript {
  /** Command name on the client; prefixed so it cannot shadow a real ioredis method. */
  readonly name: string;
  /** Absent: the key count varies, and the caller passes it as the first argument. */
  readonly numberOfKeys?: number;
  readonly lua: string;
}

export function luaScript(name: string, numberOfKeys: number | undefined, lua: string): LuaScript {
  return { name: `acemcp_${name}`, ...(numberOfKeys === undefined ? {} : { numberOfKeys }), lua };
}

type ScriptArg = string | number | Buffer;
type ScriptFn = (...args: ScriptArg[]) => Promise<unknown>;

/** Scripts already defined per client, so each is registered once per connection object. */
const defined = new WeakMap<Redis, Set<string>>();

function command(redis: Redis, s: LuaScript, suffix: '' | 'Buffer'): ScriptFn {
  let names = defined.get(redis);
  if (!names) defined.set(redis, (names = new Set()));
  if (!names.has(s.name)) {
    redis.defineCommand(s.name, { ...(s.numberOfKeys === undefined ? {} : { numberOfKeys: s.numberOfKeys }), lua: s.lua });
    names.add(s.name);
  }
  return (redis as unknown as Record<string, ScriptFn>)[s.name + suffix].bind(redis);
}

/** Defines `s` on `redis` (once per client) and runs it with KEYS followed by ARGV. */
export function runScript(redis: Redis, s: LuaScript, ...args: ScriptArg[]): Promise<unknown> {
  return command(redis, s, '')(...args);
}

/** As `runScript`, but bulk string replies come back as Buffers (binary-safe values). */
export function runScriptBuffer(redis: Redis, s: LuaScript, ...args: ScriptArg[]): Promise<unknown> {
  return command(redis, s, 'Buffer')(...args);
}

/** What ioredis `exec()` resolves to for MULTI and pipelines: null when a transaction aborted. */
export type ExecResult = [error: Error | null, result: unknown][] | null;

/**
 * ioredis reports per-command MULTI/pipeline errors in the result tuples rather than rejecting.
 * Throws `"<what> failed"` (with the cause) for an aborted transaction or the first failed command.
 */
export function checkExec(what: string, res: ExecResult): [Error | null, unknown][] {
  if (res === null) throw new Error(`${what} failed`, { cause: new Error('transaction aborted') });
  const err = res.find(([e]) => e !== null)?.[0];
  if (err) throw new Error(`${what} failed`, { cause: err });
  return res;
}
