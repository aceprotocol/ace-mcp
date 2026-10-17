import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { Redis } from 'ioredis';
import { RateLimitedError, RateLimiter } from '../../src/store/rate-limit.js';
import { RATE_PREFIX } from '../../src/store/keyspace.js';
import { REDIS } from '../helpers/stack.js';

const redis = new Redis(REDIS(47));
beforeEach(async () => { await redis.flushdb(); });
afterAll(async () => { await redis.quit(); });

describe('RateLimiter', () => {
  it('counts concurrent hits atomically and always sets the window TTL', async () => {
    const rl = new RateLimiter(redis);
    const hits = await Promise.all(Array.from({ length: 50 }, () => rl.hit('b', 10, 30)));
    expect(hits.filter((h) => h.allowed)).toHaveLength(10);
    expect(await redis.get(RATE_PREFIX + 'b')).toBe('50');
    const ttl = await redis.ttl(RATE_PREFIX + 'b');
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(30);
  });

  it('enforce throws RateLimitedError with the seconds to wait over the limit', async () => {
    const rl = new RateLimiter(redis);
    await rl.enforce('e', 1, 60);
    const err = await rl.enforce('e', 1, 60).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RateLimitedError);
    expect((err as RateLimitedError).retryAfter).toBeGreaterThan(0);
  });
});
