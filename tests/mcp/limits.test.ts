import { afterAll, beforeAll, expect, it, vi } from 'vitest';
import { buildApp } from '../../src/app.js';
import { createStack, type Stack } from '../helpers/stack.js';
import { startListening } from '../helpers/client.js';
let stack: Stack, service: Awaited<ReturnType<typeof buildApp>>;
beforeAll(async () => { stack = await createStack(40); service = await buildApp({ config: { ...stack.config, toolRateLimit: 2 }, redis: stack.redis, relayFetch: stack.relay.fetch }); await startListening(service); });
afterAll(async () => { await service.app.close(); await stack.close(); });
it('bounds token guessing per IP and returns Retry-After', async () => {
  const call = () => service.app.inject({ method: 'POST', url: '/oauth/token', headers: { host: 'localhost', 'content-type': 'application/x-www-form-urlencoded' }, payload: 'grant_type=authorization_code&code=bad' });
  await call(); await call(); const r = await call(); expect(r.statusCode).toBe(429); expect(Number(r.headers['retry-after'])).toBeGreaterThan(0);
});
it('unauthenticated flood gets 429 before 401', async () => {
  const call = () => service.app.inject({ method: 'POST', url: '/mcp', remoteAddress: '198.51.100.7', headers: { host: 'localhost', 'content-type': 'application/json', authorization: 'Bearer guess' }, payload: '{}' });
  expect((await call()).statusCode).toBe(401);
  expect((await call()).statusCode).toBe(401);
  const r = await call();
  expect(r.statusCode).toBe(429);
  expect(Number(r.headers['retry-after'])).toBeGreaterThan(0);
});
it('the owner API is limited per IP before the owner token is checked', async () => {
  const call = () => service.app.inject({ method: 'POST', url: '/owner', remoteAddress: '198.51.100.8', headers: { host: 'localhost', authorization: 'Bearer ace_mcp_' + 'x'.repeat(43) }, payload: { action: 'export' } });
  expect((await call()).statusCode).toBe(401);
  expect((await call()).statusCode).toBe(401);
  const r = await call();
  expect(r.statusCode).toBe(429);
  expect(Number(r.headers['retry-after'])).toBeGreaterThan(0);
});
it('an over-limit /mcp request never looks up its token', async () => {
  const resolve = vi.spyOn(service.grants, 'resolve');
  try {
    const call = () => service.app.inject({ method: 'POST', url: '/mcp', remoteAddress: '198.51.100.9', headers: { host: 'localhost', 'content-type': 'application/json', authorization: 'Bearer guess' }, payload: '{}' });
    await call(); await call();
    expect(resolve).toHaveBeenCalledTimes(2);
    expect((await call()).statusCode).toBe(429);
    expect(resolve).toHaveBeenCalledTimes(2);
  } finally { resolve.mockRestore(); }
});
it('/owner and /mcp count in separate per-IP buckets', async () => {
  const mcp = () => service.app.inject({ method: 'POST', url: '/mcp', remoteAddress: '198.51.100.10', headers: { host: 'localhost', 'content-type': 'application/json' }, payload: '{}' });
  await mcp(); await mcp();
  expect((await mcp()).statusCode).toBe(429);
  const owner = await service.app.inject({ method: 'POST', url: '/owner', remoteAddress: '198.51.100.10', headers: { host: 'localhost', authorization: 'Bearer ace_mcp_' + 'x'.repeat(43) }, payload: { action: 'export' } });
  expect(owner.statusCode).toBe(401);
});
