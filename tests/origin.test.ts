import { describe, expect, it } from 'vitest';
import { isLoopbackHost, originAllowed } from '../src/app.js';

const HOSTS = ['mcp.example', 'localhost', '127.0.0.1', '[::1]'];

describe('originAllowed (DNS-rebinding guard)', () => {
  it('allows no Origin and an https origin of an allowed host on the default port', () => {
    expect(originAllowed(undefined, HOSTS)).toBe(true);
    expect(originAllowed('https://mcp.example', HOSTS)).toBe(true);
    expect(originAllowed('https://MCP.example:443', HOSTS)).toBe(true); // explicit default port
  });

  it('rejects a non-default port, plain http and other schemes for a public host', () => {
    expect(originAllowed('https://mcp.example:8443', HOSTS)).toBe(false);
    expect(originAllowed('http://mcp.example', HOSTS)).toBe(false);
    expect(originAllowed('http://mcp.example:80', HOSTS)).toBe(false);
    expect(originAllowed('ws://mcp.example', HOSTS)).toBe(false);
    expect(originAllowed('chrome-extension://mcp.example', HOSTS)).toBe(false);
  });

  it('rejects hosts not in ALLOWED_HOSTS, the opaque null origin, and non-origins', () => {
    expect(originAllowed('https://evil.example', HOSTS)).toBe(false);
    expect(originAllowed('https://mcp.example.evil.example', HOSTS)).toBe(false);
    expect(originAllowed('null', HOSTS)).toBe(false);
    expect(originAllowed('garbage', HOSTS)).toBe(false);
    expect(originAllowed('https://user@mcp.example', HOSTS)).toBe(false);
    expect(originAllowed('https://mcp.example/path', HOSTS)).toBe(false);
  });

  it('allows http or https on any port for an allowed loopback host (development)', () => {
    expect(originAllowed('http://127.0.0.1:54321', HOSTS)).toBe(true);
    expect(originAllowed('http://localhost:3100', HOSTS)).toBe(true);
    expect(originAllowed('https://localhost:8443', HOSTS)).toBe(true);
    expect(originAllowed('http://[::1]:3100', HOSTS)).toBe(true);
    expect(originAllowed('http://127.0.0.2:3100', HOSTS)).toBe(false); // loopback, but not allowed
    expect(originAllowed('ftp://localhost', HOSTS)).toBe(false);
  });

  it('isLoopbackHost', () => {
    for (const h of ['localhost', 'app.localhost', '127.0.0.1', '127.1.2.3', '[::1]']) expect(isLoopbackHost(h)).toBe(true);
    for (const h of ['mcp.example', '128.0.0.1', '10.0.0.1', 'localhost.example', '[::2]']) expect(isLoopbackHost(h)).toBe(false);
  });
});
