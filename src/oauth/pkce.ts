import { createHash, timingSafeEqual } from 'node:crypto';
import { isOpaque } from '../identity/token.js';

/** RFC 7636 § 4.1 / § 4.2: 43–128 characters of [A-Za-z0-9-._~] (verifier and challenge alike). */
const PKCE_RE = /^[A-Za-z0-9._~-]{43,128}$/;

export function isPkceString(v: unknown): v is string {
  return typeof v === 'string' && PKCE_RE.test(v);
}

/** An S256 code_challenge: BASE64URL of a 32-byte SHA-256 digest, no padding — exactly 43 characters. */
export function isS256Challenge(v: unknown): v is string {
  return isOpaque(v);
}

/** BASE64URL(SHA256(ASCII(code_verifier))) — RFC 7636 § 4.2, method S256. */
export function s256Challenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/** Constant-time check that `verifier` is well-formed and hashes to `challenge`. */
export function verifyS256(verifier: string, challenge: string): boolean {
  if (!isPkceString(verifier) || typeof challenge !== 'string') return false;
  const a = Buffer.from(s256Challenge(verifier));
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
}
