import type { Redis } from 'ioredis';
import { RATE_PREFIX } from './keyspace.js';
import { luaScript, runScript } from './scripts.js';

// Atomic fixed window: INCR, set the window TTL on the first hit, return [count, ttl].
// KEYS[1] bucket, ARGV[1] window seconds.
const HIT = luaScript('rate_hit', 1, `
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return {n, redis.call('TTL', KEYS[1])}`);

/** Over a limit; each boundary (MCP tool, OAuth page, JSON endpoint) reports it in its own shape. */
export class RateLimitedError extends Error {
  constructor(message: string, readonly retryAfter: number) {
    super(message);
    this.name = 'RateLimitedError';
  }
}

export interface RateHit {
  allowed: boolean;
  /** Seconds until the window resets (≥ 1). */
  retryAfter: number;
}

export class RateLimiter {
  constructor(private redis: Redis) {}

  /** Count one hit in the bucket's fixed window. */
  async hit(bucket: string, limit: number, windowSeconds: number): Promise<RateHit> {
    const [count, ttl] = (await runScript(this.redis, HIT, RATE_PREFIX + bucket, String(windowSeconds))) as [number, number];
    return { allowed: count <= limit, retryAfter: Math.max(ttl, 1) };
  }

  /** Fixed window; throws RateLimitedError over the limit. */
  async enforce(bucket: string, limit: number, windowSeconds: number): Promise<void> {
    const r = await this.hit(bucket, limit, windowSeconds);
    if (!r.allowed) throw new RateLimitedError(`rate limit exceeded; retry in ${r.retryAfter}s`, r.retryAfter);
  }
}
