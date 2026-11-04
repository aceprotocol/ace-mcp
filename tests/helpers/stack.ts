import { Redis } from 'ioredis';
import { loadConfig, type McpConfig } from '../../src/config.js';
import { buildApp, type McpApp } from '../../src/app.js';
import { FakeRelay, RELAY } from './fake-relay.js';

export const REDIS = (db: number) => `${process.env.ACE_TEST_REDIS_ORIGIN ?? 'redis://localhost:16379'}/${db}`;
const MIN_DATABASES = 64;

export interface Stack {
  relay: FakeRelay;
  redis: Redis;
  config: McpConfig;
  service: McpApp;
  close(): Promise<void>;
}

async function assertDatabases(r: Redis): Promise<void> {
  const res = (await r.config('GET', 'databases')) as string[];
  if (!(Number(res[1]) >= MIN_DATABASES)) {
    throw new Error(`dev Redis on localhost:16379 has ${res[1] ?? '?'} databases; tests need at least ${MIN_DATABASES}. Start it with: redis-server --port 16379 --save '' --databases 64`);
  }
}

/** An in-memory relay plus the MCP service on Redis db `db` (flushed). */
export async function createStack(db: number, env: Record<string, string> = {}): Promise<Stack> {
  const redis = new Redis(REDIS(db));
  try {
    await assertDatabases(redis);
    await redis.flushdb();
    const relay = new FakeRelay();
    const config = loadConfig({
      MCP_KEK: Buffer.alloc(32, 5).toString('base64'), RELAY_URL: RELAY, PUBLIC_RELAY_URL: RELAY,
      ALLOWED_HOSTS: 'localhost,127.0.0.1', REDIS_URL: REDIS(db), TOOL_RATE_LIMIT: '10000', IDENTITY_CREATE_RATE_LIMIT: '1000', ...env,
    });
    const service = await buildApp({ config, redis, relayFetch: relay.fetch });
    return { relay, redis, config, service, close: async () => { await service.app.close(); await redis.quit(); } };
  } catch (e) {
    await redis.quit();
    throw e;
  }
}
