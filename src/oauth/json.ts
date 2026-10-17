import type { FastifyReply } from 'fastify';
import type { RateLimiter } from '../store/rate-limit.js';

/** An RFC 6749 § 5.2-shaped JSON error. */
export function oauthError(reply: FastifyReply, status: number, error: string, description: string): FastifyReply {
  return reply.code(status).send({ error, error_description: description });
}

/** Count one hit; over the limit, answers 429 `rate_limited` and returns false. */
export async function withinLimit(
  reply: FastifyReply,
  limiter: RateLimiter,
  limit: { bucket: string; max: number; windowSeconds: number; what: string },
): Promise<boolean> {
  const hit = await limiter.hit(limit.bucket, limit.max, limit.windowSeconds);
  if (hit.allowed) return true;
  reply.header('retry-after', String(hit.retryAfter));
  oauthError(reply, 429, 'rate_limited', `too many ${limit.what}; retry in ${hit.retryAfter}s`);
  return false;
}
