import { AgentWorkers } from './agent/workers.js';
import Fastify from 'fastify';
import { Redis } from 'ioredis';
import { loadConfig, type McpConfig } from './config.js';
import { buildApp } from './app.js';
import { IDENTITIES_INDEX } from './store/keyspace.js';

/** Backstop: a hung close must not outlive Docker's SIGKILL grace period (10 s). */
const SHUTDOWN_BACKSTOP_MS = 8000;

let config: McpConfig;
try {
  config = loadConfig();
} catch (err) {
  console.error(`ace-mcp: invalid configuration: ${(err as Error).message}`);
  process.exit(1);
}

const redis = new Redis(config.redisUrl, { maxRetriesPerRequest: 3 });
const { app, vault, telemetry, runtime } = await buildApp({ config, redis, logger: true });

const workers = new AgentWorkers(runtime, vault, app.log);
workers.start();
app.addHook('onClose', async () => { await workers.stop(); });

const metrics = Fastify({ logger: false });
metrics.get('/metrics', async (_req, reply) => reply
  .type('text/plain; version=0.0.4')
  .send(telemetry.render({ identities: await redis.zcard(IDENTITIES_INDEX), receivers: runtime.receivers.size })));

await app.listen({ host: '0.0.0.0', port: config.port });
await metrics.listen({ host: '0.0.0.0', port: config.metricsPort });
app.log.info(`ace-mcp listening on :${config.port}, metrics on :${config.metricsPort}`);

let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  app.log.info({ signal }, 'shutting down');
  setTimeout(() => process.exit(0), SHUTDOWN_BACKSTOP_MS).unref();
  try {
    await app.close();
    await metrics.close();
  } catch (err) {
    app.log.error({ err }, 'shutdown failed');
  }
  redis.disconnect();
  process.exit(0);
}
process.on('SIGTERM', () => { void shutdown('SIGTERM'); });
process.on('SIGINT', () => { void shutdown('SIGINT'); });
