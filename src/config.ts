import { readFileSync, statSync } from 'node:fs';
import { MAX_PACKET_BYTES, isCanonicalRelayUrl, normalizeRelayUrl } from '@ace-protocol/sdk';

export interface McpConfig {
  port: number;
  metricsPort: number;
  redisUrl: string;
  relayUrl: string;
  publicRelayUrl: string;
  kek: Buffer;
  trustProxy: boolean | string;
  allowedHosts: string[];
  identityCreateRateLimit: number;
  /** Per identity per minute for identity tools; also per IP per minute for the public tools. */
  toolRateLimit: number;
  /** Read messages are deleted this long after they were received. */
  messageRetentionDays: number;
  /** Unread messages per identity; past it the receiver leaves packets on the relay (back-pressure). */
  maxUnreadMessages: number;
  /**
   * Sealed bytes per identity store (messages, Outbox, SDK state). A message that does not fit evicts read messages,
   * oldest first; when unread messages fill it, the receiver leaves packets on the relay (back-pressure).
   */
  maxStoreBytes: number;
}

type Env = Record<string, string | undefined>;

/** A non-negative integer, at least `min`; with `max`, within [min, max]. */
function envInt(env: Env, key: string, fallback: number, { min = 0, max }: { min?: number; max?: number } = {}): number {
  const t = env[key]?.trim();
  if (t === undefined || t === '') return fallback;
  if (!/^[0-9]+$/.test(t) || !Number.isSafeInteger(Number(t))) throw new Error(`${key}=${t}: expected a non-negative integer`);
  const v = Number(t);
  if (max !== undefined && (v < min || v > max)) throw new Error(`${key}=${v}: expected ${min}–${max}`);
  if (v < min) throw new Error(`${key} must be at least ${min}`);
  return v;
}

function required(env: Env, key: string): string {
  const v = env[key]?.trim();
  if (!v) throw new Error(`${key} is required`);
  return v;
}

function envTrustProxy(env: Env): boolean | string {
  const t = env.TRUST_PROXY?.trim();
  if (!t) return false;
  if (t === 'true') return true;
  if (t === 'false') return false;
  if (/^\d+$/.test(t)) throw new Error(`TRUST_PROXY=${t}: hop counts are not supported — set the proxy's IP/CIDR`);
  return t;
}

/** Canonical Base64 of exactly 32 bytes. */
function parseKek(text: string, source: string): Buffer {
  const kek = Buffer.from(text, 'base64');
  if (kek.length !== 32 || kek.toString('base64') !== text) throw new Error(`${source} must be the Base64 of 32 random bytes`);
  return kek;
}

/**
 * Reads a secret file: it must not be group- or world-accessible (POSIX mode & 0o077 == 0); one
 * trailing newline is stripped. Errors name the variable and path, never the content.
 */
function readSecretFile(key: string, file: string): string {
  let mode: number;
  let text: string;
  try {
    mode = statSync(file).mode;
    text = readFileSync(file, 'utf8');
  } catch (e) {
    throw new Error(`${key}=${file}: cannot read (${(e as NodeJS.ErrnoException).code ?? 'error'})`);
  }
  if (process.platform !== 'win32' && (mode & 0o077) !== 0) {
    throw new Error(`${key}=${file}: mode ${(mode & 0o777).toString(8).padStart(4, '0')} is group/world-accessible; chmod 0400 (or 0600) it`);
  }
  return text.replace(/\r?\n$/, '');
}

/**
 * A secret from `<key>_FILE` (read with readSecretFile) or `<key>`, not both; null when neither is
 * set. `source` names where it came from, for error messages (never the value).
 */
function envSecret(env: Env, key: string): { value: string; source: string; fromFile: boolean } | null {
  const file = env[`${key}_FILE`]?.trim();
  const inline = env[key]?.trim();
  if (file && inline) throw new Error(`set either ${key}_FILE or ${key}, not both`);
  if (file) return { value: readSecretFile(`${key}_FILE`, file), source: `${key}_FILE=${file}`, fromFile: true };
  return inline ? { value: inline, source: key, fromFile: false } : null;
}

/**
 * The KEK from MCP_KEK_FILE (preferred: the secret stays out of the environment and `docker inspect`)
 * or MCP_KEK; exactly one of them.
 */
function loadKek(env: Env): Buffer {
  const s = envSecret(env, 'MCP_KEK');
  if (!s) throw new Error('MCP_KEK is required');
  return parseKek(s.value, s.source);
}

/**
 * The Redis URL from REDIS_URL_FILE (preferred in deploy: the URL carries the Valkey password) or
 * REDIS_URL; not both. Default `redis://localhost:6379`.
 */
function loadRedisUrl(env: Env): string {
  const s = envSecret(env, 'REDIS_URL');
  if (!s) return 'redis://localhost:6379';
  if (!s.fromFile) return s.value;
  const url = s.value.trim();
  if (!/^rediss?:\/\/\S+$/.test(url)) throw new Error(`${s.source}: expected a redis:// or rediss:// URL`);
  return url;
}

/**
 * PUBLIC_RELAY_URL is the audience every relay request signs and the route every descriptor advertises: it must be the
 * canonical https form (02 § Relay URL) the relay and verifiers compare byte for byte.
 */
function publicRelayUrl(env: Env): string {
  const v = required(env, 'PUBLIC_RELAY_URL');
  if (isCanonicalRelayUrl(v, { allowLoopback: false })) return v;
  let hint = '';
  try { hint = `; did you mean ${normalizeRelayUrl(v)}?`; } catch { /* not a URL */ }
  throw new Error(`PUBLIC_RELAY_URL=${v}: expected a canonical https relay URL (lowercase host, no default port, trailing slash, query or fragment)${hint}`);
}

const PORT = { min: 1, max: 65535 };
const MiB = 1024 * 1024;

export function loadConfig(env: Env = process.env): McpConfig {
  const kek = loadKek(env);
  const allowedHosts = required(env, 'ALLOWED_HOSTS').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
  if (allowedHosts.length === 0) throw new Error('ALLOWED_HOSTS must list at least one host');
  // A floor of 1 where 0 would be destructive: retention 0 deletes every read message at once.
  return {
    port: envInt(env, 'PORT', 3100, PORT),
    metricsPort: envInt(env, 'METRICS_PORT', 9100, PORT),
    redisUrl: loadRedisUrl(env),
    relayUrl: required(env, 'RELAY_URL'),
    publicRelayUrl: publicRelayUrl(env),
    kek,
    trustProxy: envTrustProxy(env),
    allowedHosts,
    identityCreateRateLimit: envInt(env, 'IDENTITY_CREATE_RATE_LIMIT', 5),
    toolRateLimit: envInt(env, 'TOOL_RATE_LIMIT', 120, { min: 1 }),
    messageRetentionDays: envInt(env, 'MESSAGE_RETENTION_DAYS', 30, { min: 1 }),
    maxUnreadMessages: envInt(env, 'MAX_UNREAD_MESSAGES', 1000, { min: 1, max: 100_000 }),
    // At least room for a full-size packet beside the identity's state, or one large message would block the inbox.
    maxStoreBytes: envInt(env, 'MAX_STORE_BYTES', 16 * MiB, { min: 2 * MAX_PACKET_BYTES, max: 1024 * MiB }),
  };
}
