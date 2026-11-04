import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

const NONCE_LEN = 12;
const TAG_LEN = 16;

/** Nonce + tag: a sealed empty plaintext is exactly this long; anything shorter is not a sealed blob. */
export const SEALED_OVERHEAD = NONCE_LEN + TAG_LEN;

/**
 * A sealed blob could not be opened: wrong key, tampered or truncated data, or a blob moved to
 * another place (AAD). Never retryable. Carries where it was read from (when the reader knows),
 * never the blob itself.
 */
export class SealedDataError extends Error {
  aceId?: string;
  key?: string;
  constructor(message: string, opts: { cause?: unknown; aceId?: string; key?: string } = {}) {
    super(message, opts.cause !== undefined ? { cause: opts.cause } : undefined);
    this.name = 'SealedDataError';
    if (opts.aceId !== undefined) this.aceId = opts.aceId;
    if (opts.key !== undefined) this.key = opts.key;
  }
}

/** Runs `read`; a SealedDataError it throws is tagged with where the blob was read from. */
export function locateSealed<T>(aceId: string, key: string, read: () => T): T {
  try {
    return read();
  } catch (e) {
    if (e instanceof SealedDataError) {
      e.aceId = aceId;
      e.key = key;
    }
    throw e;
  }
}

const HKDF_SALT = 'ace-mcp/v1';

/** What a derived key encrypts: identity seeds, prekey seeds, or ACEStore values (messages, peers, outbox, settings). */
export type SubkeyPurpose = 'identity' | 'prekey' | 'store';

/**
 * Per-identity subkey: HKDF-SHA256(ikm = MCP_KEK, salt = "ace-mcp/v1", info = "<purpose>\0<aceId>", 32 bytes).
 * Every sealed blob is under a subkey, never the KEK itself: the random-nonce budget (about 2^32 seals per key)
 * applies per identity and purpose, and identity seeds, prekey seeds and store values are cryptographically separated.
 */
export function deriveSubkey(kek: Buffer, purpose: SubkeyPurpose, aceId: string): Buffer {
  if (kek.length !== 32) throw new Error('KEK must be 32 bytes');
  return Buffer.from(hkdfSync('sha256', kek, HKDF_SALT, `${purpose}\0${aceId}`, 32));
}

/**
 * A non-secret identifier of the KEK (16 hex characters, HKDF info "kek-id"), stored next to each identity blob so
 * a record sealed under another KEK is reported as such instead of as tampering, and a future KEK rotation can
 * find the records it still has to re-seal.
 */
export function kekId(kek: Buffer): string {
  if (kek.length !== 32) throw new Error('KEK must be 32 bytes');
  return Buffer.from(hkdfSync('sha256', kek, HKDF_SALT, 'kek-id', 8)).toString('hex');
}

/**
 * AES-256-GCM under the service key-encryption key (MCP_KEK). Output layout nonce ‖ ciphertext ‖ tag;
 * the AAD binds a blob to its place (record type, aceId, key), so it cannot be moved elsewhere.
 * `open` throws SealedDataError on a wrong key, a tampered or short blob or a different AAD.
 */
export interface KekCipher {
  seal(aad: string, plaintext: Uint8Array | string): Buffer;
  open(aad: string, blob: Uint8Array): Buffer;
}

export function kekCipher(kek: Buffer): KekCipher {
  if (kek.length !== 32) throw new Error('KEK must be 32 bytes');
  const key = Buffer.from(kek); // own copy: the caller's buffer may be reused
  return {
    seal(aad, plaintext) {
      const nonce = randomBytes(NONCE_LEN);
      const c = createCipheriv('aes-256-gcm', key, nonce);
      c.setAAD(Buffer.from(aad));
      const data = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;
      return Buffer.concat([nonce, c.update(data), c.final(), c.getAuthTag()]);
    },
    open(aad, blob) {
      if (blob.length < SEALED_OVERHEAD) throw new SealedDataError('sealed blob too short');
      const raw = Buffer.from(blob.buffer, blob.byteOffset, blob.byteLength);
      try {
        const d = createDecipheriv('aes-256-gcm', key, raw.subarray(0, NONCE_LEN), { authTagLength: TAG_LEN });
        d.setAAD(Buffer.from(aad));
        d.setAuthTag(raw.subarray(raw.length - TAG_LEN));
        return Buffer.concat([d.update(raw.subarray(NONCE_LEN, raw.length - TAG_LEN)), d.final()]);
      } catch (e) {
        throw new SealedDataError('sealed blob could not be decrypted', { cause: e });
      }
    },
  };
}
