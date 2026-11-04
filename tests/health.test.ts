import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Redis } from 'ioredis';
import { createStack, type Stack } from './helpers/stack.js';
import { buildApp } from '../src/app.js';

let stack: Stack;
beforeAll(async () => { stack = await createStack(51); });
afterAll(() => stack?.close());

describe('/health', () => {
  it('is 200 while Redis answers', async () => {
    const r = await stack.service.app.inject({ method: 'GET', url: '/health', headers: { host: 'localhost' } });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toEqual({ ok: true });
  });

  it('is 503 when Redis does not answer', async () => {
    const down = new Redis('redis://127.0.0.1:1', { lazyConnect: true, enableOfflineQueue: false, maxRetriesPerRequest: 0, retryStrategy: () => null });
    const { app } = await buildApp({ config: stack.config, redis: down, relayFetch: stack.relay.fetch });
    try {
      const r = await app.inject({ method: 'GET', url: '/health', headers: { host: 'localhost' } });
      expect(r.statusCode).toBe(503);
      expect(r.json()).toEqual({ ok: false, error: 'redis_unavailable' });
    } finally {
      await app.close();
      down.disconnect();
    }
  });
});
