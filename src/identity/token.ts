import { randomBytes } from 'node:crypto';
import { sha256Hex } from '@ace-protocol/sdk';

/** 32 random bytes as base64url: exactly 43 characters. */
const OPAQUE_RE = /^[A-Za-z0-9_-]{43}$/;
const TOKEN_RE = /^ace_mcp_[A-Za-z0-9_-]{43}$/;

/** 32 random bytes, base64url (43 characters): tokens, OAuth client ids, codes and page nonces. */
export function randomOpaque(): string {
  return randomBytes(32).toString('base64url');
}

export function isOpaque(v: unknown): v is string {
  return typeof v === 'string' && OPAQUE_RE.test(v);
}

export function generateToken(): { token: string; hash: string } {
  const token = 'ace_mcp_' + randomOpaque();
  return { token, hash: sha256Hex(token) };
}

export function isTokenShape(v: unknown): v is string {
  return typeof v === 'string' && TOKEN_RE.test(v);
}
