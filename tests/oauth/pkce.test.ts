import { describe, expect, it } from 'vitest';
import { isPkceString, s256Challenge, verifyS256 } from '../../src/oauth/pkce.js';

// RFC 7636 Appendix B.
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

describe('PKCE S256', () => {
  it('matches the RFC 7636 Appendix B vector', () => {
    expect(s256Challenge(VERIFIER)).toBe(CHALLENGE);
    expect(verifyS256(VERIFIER, CHALLENGE)).toBe(true);
  });

  it('rejects a wrong or malformed verifier', () => {
    expect(verifyS256(VERIFIER.slice(0, -1) + 'l', CHALLENGE)).toBe(false);
    expect(verifyS256('short', s256Challenge('short'))).toBe(false); // < 43 chars
    expect(verifyS256(VERIFIER, CHALLENGE.slice(1))).toBe(false); // length mismatch, no throw
  });

  it('accepts only 43–128 chars of the unreserved set', () => {
    expect(isPkceString('a'.repeat(43))).toBe(true);
    expect(isPkceString('a'.repeat(128))).toBe(true);
    expect(isPkceString('a'.repeat(42))).toBe(false);
    expect(isPkceString('a'.repeat(129))).toBe(false);
    expect(isPkceString('A-._~' + 'z'.repeat(40))).toBe(true);
    expect(isPkceString('a'.repeat(42) + '+')).toBe(false);
    expect(isPkceString(undefined)).toBe(false);
  });
});
