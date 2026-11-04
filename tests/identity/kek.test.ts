import { describe, expect, it } from 'vitest';
import { hkdfSync } from 'node:crypto';
import { SEALED_OVERHEAD, SealedDataError, deriveSubkey, kekCipher, kekId } from '../../src/identity/kek.js';

const KEK = Buffer.alloc(32, 7);

describe('KekCipher', () => {
  it('round-trips an empty plaintext (a sealed empty value is exactly SEALED_OVERHEAD bytes)', () => {
    const c = kekCipher(KEK);
    const blob = c.seal('aad', new Uint8Array(0));
    expect(blob.length).toBe(SEALED_OVERHEAD);
    expect(c.open('aad', blob).length).toBe(0);
  });

  it('throws SealedDataError for a short blob, a tampered blob, a wrong AAD and a wrong key', () => {
    const c = kekCipher(KEK);
    const blob = c.seal('aad', 'hello');
    expect(() => c.open('aad', blob.subarray(0, SEALED_OVERHEAD - 1))).toThrow(SealedDataError);
    const tampered = Buffer.from(blob);
    tampered[SEALED_OVERHEAD - 16] ^= 1;
    expect(() => c.open('aad', tampered)).toThrow(SealedDataError);
    expect(() => c.open('other', blob)).toThrow(SealedDataError);
    expect(() => kekCipher(Buffer.alloc(32, 8)).open('aad', blob)).toThrow(SealedDataError);
    expect(c.open('aad', blob).toString()).toBe('hello');
  });
});

describe('deriveSubkey', () => {
  const A = 'ace:sha256:' + 'a'.repeat(64);
  const B = 'ace:sha256:' + 'b'.repeat(64);
  it('is HKDF-SHA256(KEK, salt "ace-mcp/v1", info "<purpose>\\0<aceId>", 32) and deterministic', () => {
    const k = deriveSubkey(KEK, 'store', A);
    expect(k).toHaveLength(32);
    expect(deriveSubkey(KEK, 'store', A).equals(k)).toBe(true);
    expect(k.equals(Buffer.from(hkdfSync('sha256', KEK, Buffer.from('ace-mcp/v1', 'ascii'), Buffer.from(`store\u0000${A}`), 32)))).toBe(true);
  });
  it('differs per identity, per purpose and per KEK, and never equals the KEK', () => {
    const k = deriveSubkey(KEK, 'store', A);
    expect(deriveSubkey(KEK, 'store', B).equals(k)).toBe(false);
    expect(deriveSubkey(KEK, 'prekey', A).equals(k)).toBe(false);
    expect(deriveSubkey(KEK, 'identity', A).equals(k)).toBe(false);
    expect(deriveSubkey(Buffer.alloc(32, 8), 'store', A).equals(k)).toBe(false);
    expect(k.equals(KEK)).toBe(false);
  });
});

describe('kekId', () => {
  it('is a stable 16-hex identifier that differs per KEK and reveals nothing usable as a key', () => {
    expect(kekId(KEK)).toMatch(/^[0-9a-f]{16}$/);
    expect(kekId(KEK)).toBe(kekId(Buffer.from(KEK)));
    expect(kekId(Buffer.alloc(32, 8))).not.toBe(kekId(KEK));
  });
});
