import { afterAll, beforeAll, describe, it, expect } from 'vitest';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../src/config.js';

const KEK = Buffer.alloc(32, 1).toString('base64');
const base = { MCP_KEK: KEK, RELAY_URL: 'http://127.0.0.1:3000', PUBLIC_RELAY_URL: 'https://relay.aceprotocol.org', ALLOWED_HOSTS: 'mcp.aceprotocol.org,localhost' };

describe('loadConfig', () => {
  it('reads defaults and required values', () => {
    const c = loadConfig(base);
    expect(c.port).toBe(3100);
    expect(c.kek).toHaveLength(32);
    expect(c.allowedHosts).toEqual(['mcp.aceprotocol.org', 'localhost']);
    expect(c.identityCreateRateLimit).toBe(5);
    expect(c.toolRateLimit).toBe(120);
  });


  it('fails without a 32-byte KEK', () => {
    expect(() => loadConfig({ ...base, MCP_KEK: 'short' })).toThrow('MCP_KEK');
    expect(() => loadConfig({ ...base, MCP_KEK: undefined })).toThrow('MCP_KEK');
  });
  it('requires RELAY_URL, PUBLIC_RELAY_URL and ALLOWED_HOSTS', () => {
    for (const k of ['RELAY_URL', 'PUBLIC_RELAY_URL', 'ALLOWED_HOSTS']) expect(() => loadConfig({ ...base, [k]: '' })).toThrow(k);
  });
  it('requires PUBLIC_RELAY_URL in canonical form (https, normalized: the signed audience)', () => {
    expect(loadConfig({ ...base, PUBLIC_RELAY_URL: 'https://relay.example.org/ace' }).publicRelayUrl).toBe('https://relay.example.org/ace');
    for (const bad of ['https://relay.aceprotocol.org/', 'https://Relay.aceprotocol.org', 'https://relay.aceprotocol.org:443', 'http://relay.aceprotocol.org', 'http://localhost:3000', 'https://relay.aceprotocol.org?x=1', 'relay.aceprotocol.org']) {
      expect(() => loadConfig({ ...base, PUBLIC_RELAY_URL: bad }), bad).toThrow('PUBLIC_RELAY_URL');
    }
  });
  it('rejects a hop-count TRUST_PROXY like the relay does', () => {
    expect(() => loadConfig({ ...base, TRUST_PROXY: '1' })).toThrow('TRUST_PROXY');
  });
});

describe('loadConfig MCP_KEK_FILE', () => {
  let dir: string;
  beforeAll(() => { dir = mkdtempSync(join(tmpdir(), 'ace-mcp-kek-')); });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const { MCP_KEK: _omit, ...noKek } = base;
  const file = (name: string, content: string, mode: number): string => {
    const p = join(dir, name);
    writeFileSync(p, content);
    chmodSync(p, mode);
    return p;
  };

  it('reads a 0600 file (trailing newline tolerated) and a 0400 file', () => {
    expect(loadConfig({ ...noKek, MCP_KEK_FILE: file('ok600', `${KEK}\n`, 0o600) }).kek.equals(Buffer.alloc(32, 1))).toBe(true);
    expect(loadConfig({ ...noKek, MCP_KEK_FILE: file('ok400', KEK, 0o400) }).kek.equals(Buffer.alloc(32, 1))).toBe(true);
  });
  it.skipIf(process.platform === 'win32')('refuses a group/world-readable file', () => {
    expect(() => loadConfig({ ...noKek, MCP_KEK_FILE: file('wide', KEK, 0o644) })).toThrow(/group\/world-accessible/);
    expect(() => loadConfig({ ...noKek, MCP_KEK_FILE: file('group', KEK, 0o640) })).toThrow(/0640/);
  });
  it('refuses bad content without echoing it', () => {
    let msg = '';
    try { loadConfig({ ...noKek, MCP_KEK_FILE: file('bad', 'not-a-kek-value\n', 0o600) }); } catch (e) { msg = (e as Error).message; }
    expect(msg).toMatch(/MCP_KEK_FILE=.*Base64 of 32 random bytes/);
    expect(msg).not.toContain('not-a-kek-value');
    expect(() => loadConfig({ ...noKek, MCP_KEK_FILE: file('short', Buffer.alloc(16, 1).toString('base64'), 0o600) })).toThrow('MCP_KEK_FILE');
    expect(() => loadConfig({ ...noKek, MCP_KEK_FILE: file('twonl', `${KEK}\n\n`, 0o600) })).toThrow('MCP_KEK_FILE');
  });
  it('refuses a missing file', () => {
    expect(() => loadConfig({ ...noKek, MCP_KEK_FILE: join(dir, 'nope') })).toThrow(/MCP_KEK_FILE=.*cannot read \(ENOENT\)/);
  });
  it('refuses MCP_KEK and MCP_KEK_FILE together', () => {
    expect(() => loadConfig({ ...base, MCP_KEK_FILE: file('both', KEK, 0o600) })).toThrow('either MCP_KEK_FILE or MCP_KEK');
  });
});

describe('loadConfig ports and retention', () => {
  it('requires positive message retention and a bounded unread cap', () => {
    expect(loadConfig(base)).toMatchObject({ messageRetentionDays: 30, maxUnreadMessages: 1000 });
    expect(loadConfig({ ...base, MESSAGE_RETENTION_DAYS: '1', MAX_UNREAD_MESSAGES: '5' })).toMatchObject({ messageRetentionDays: 1, maxUnreadMessages: 5 });
    expect(() => loadConfig({ ...base, MESSAGE_RETENTION_DAYS: '0' })).toThrow('MESSAGE_RETENTION_DAYS must be at least 1');
    expect(() => loadConfig({ ...base, MAX_UNREAD_MESSAGES: '0' })).toThrow('MAX_UNREAD_MESSAGES');
  });
  it('bounds the per-identity store size: room for a full-size packet, at most 1 GiB', () => {
    expect(loadConfig(base).maxStoreBytes).toBe(16 * 1024 * 1024);
    expect(loadConfig({ ...base, MAX_STORE_BYTES: String(4 * 1024 * 1024) }).maxStoreBytes).toBe(4 * 1024 * 1024);
    expect(() => loadConfig({ ...base, MAX_STORE_BYTES: String(4 * 1024 * 1024 - 1) })).toThrow('MAX_STORE_BYTES');
    expect(() => loadConfig({ ...base, MAX_STORE_BYTES: String(1024 ** 3 + 1) })).toThrow('MAX_STORE_BYTES');
  });
  it('bounds PORT and METRICS_PORT to 1–65535', () => {
    expect(loadConfig({ ...base, PORT: '65535', METRICS_PORT: '1' })).toMatchObject({ port: 65535, metricsPort: 1 });
    for (const k of ['PORT', 'METRICS_PORT']) {
      expect(() => loadConfig({ ...base, [k]: '0' })).toThrow(k);
      expect(() => loadConfig({ ...base, [k]: '65536' })).toThrow(k);
    }
  });

});

describe('loadConfig REDIS_URL_FILE', () => {
  let dir: string;
  beforeAll(() => { dir = mkdtempSync(join(tmpdir(), 'ace-mcp-redis-')); });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const URL_ = 'redis://:s3cret@relay-valkey:6379/2';
  const file = (name: string, content: string, mode: number): string => {
    const p = join(dir, name);
    writeFileSync(p, content);
    chmodSync(p, mode);
    return p;
  };

  it('defaults to localhost and reads REDIS_URL inline', () => {
    expect(loadConfig(base).redisUrl).toBe('redis://localhost:6379');
    expect(loadConfig({ ...base, REDIS_URL: URL_ }).redisUrl).toBe(URL_);
  });
  it('reads a 0600 / 0400 file (trailing newline tolerated)', () => {
    expect(loadConfig({ ...base, REDIS_URL_FILE: file('ok600', `${URL_}\n`, 0o600) }).redisUrl).toBe(URL_);
    expect(loadConfig({ ...base, REDIS_URL_FILE: file('ok400', URL_, 0o400) }).redisUrl).toBe(URL_);
  });
  it.skipIf(process.platform === 'win32')('refuses a group/world-readable file', () => {
    expect(() => loadConfig({ ...base, REDIS_URL_FILE: file('wide', URL_, 0o644) })).toThrow(/REDIS_URL_FILE=.*0644 is group\/world-accessible/);
  });
  it('refuses a missing file and non-URL content without echoing it', () => {
    expect(() => loadConfig({ ...base, REDIS_URL_FILE: join(dir, 'nope') })).toThrow(/REDIS_URL_FILE=.*cannot read \(ENOENT\)/);
    let msg = '';
    try { loadConfig({ ...base, REDIS_URL_FILE: file('bad', 'hunter2-password\n', 0o600) }); } catch (e) { msg = (e as Error).message; }
    expect(msg).toMatch(/REDIS_URL_FILE=.*redis:\/\//);
    expect(msg).not.toContain('hunter2');
  });
  it('a percent-encoded password with @ : / survives the file and decodes to the original', () => {
    const password = 'p@ss:w/rd%#?';
    const encoded = encodeURIComponent(password); // what the deploy's urllib.parse.quote(safe='') writes
    expect(encoded).toBe('p%40ss%3Aw%2Frd%25%23%3F');
    const url = loadConfig({ ...base, REDIS_URL_FILE: file('enc', `redis://:${encoded}@relay-valkey:6379/2\n`, 0o600) }).redisUrl;
    const u = new URL(url);
    expect(decodeURIComponent(u.password)).toBe(password);
    expect(u.username).toBe('');
    expect(u.hostname).toBe('relay-valkey');
    expect(u.port).toBe('6379');
    expect(u.pathname).toBe('/2');
  });
  it('refuses REDIS_URL and REDIS_URL_FILE together', () => {
    expect(() => loadConfig({ ...base, REDIS_URL: URL_, REDIS_URL_FILE: file('both', URL_, 0o600) })).toThrow('either REDIS_URL_FILE or REDIS_URL');
  });
});
