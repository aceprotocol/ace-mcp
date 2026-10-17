import { ACEError } from '@ace-protocol/sdk';
import { SealedDataError } from './identity/kek.js';
import { RateLimitedError } from './store/rate-limit.js';
import { IdentityNotFoundError } from './identity/vault.js';

export const UNAUTHENTICATED_MESSAGE =
  'Connect through OAuth and send the client access token in the Authorization header on every request.';

export class McpToolError extends Error {
  constructor(readonly code: string, message: string, readonly retryable: boolean) {
    super(message);
    this.name = 'McpToolError';
  }
}

export function unauthenticated(): McpToolError {
  return new McpToolError('unauthenticated', UNAUTHENTICATED_MESSAGE, false);
}

/** The subset of a pino/Fastify logger the error mapping uses. */
export interface ErrorLogger {
  error(obj: object, msg: string): void;
}

/** `e` itself or the first `Ctor` in its `cause` chain (the SDK may wrap a store failure). */
function findCause<T extends Error>(e: unknown, Ctor: abstract new (...args: never[]) => T): T | null {
  for (let c: unknown = e, depth = 0; c instanceof Error && depth < 8; c = c.cause, depth++) {
    if (c instanceof Ctor) return c;
  }
  return null;
}

/** The first SealedDataError (an undecryptable stored record) in `e`'s cause chain, or null. */
export const findSealedDataError = (e: unknown): SealedDataError | null => findCause(e, SealedDataError);

export const CORRUPT_RECORD_MESSAGE = 'a stored record could not be decrypted';
export const BUSY_MESSAGE = 'another call for this identity is in progress; retry';

/**
 * The one mapping from a thrown error to a tool error. SDK errors keep their code; transient and
 * local SDK categories are retryable. A stored record that cannot be decrypted (SealedDataError,
 * possibly wrapped by the SDK) is `corrupt_record`, not retryable, and logged with where it was
 * read from — never the blob. Anything unrecognized is `internal`.
 */
export function toolErrorFromACE(e: unknown, logger?: ErrorLogger): McpToolError {
  if (e instanceof McpToolError) return e;
  if (e instanceof RateLimitedError) return new McpToolError('rate_limited', e.message, true);
  // Deleted while the call ran (or a session bound to an identity deleted elsewhere).
  if (e instanceof IdentityNotFoundError) return unauthenticated();
  const sealed = findSealedDataError(e);
  if (sealed) {
    logger?.error({ code: 'corrupt_record', aceId: sealed.aceId, key: sealed.key }, CORRUPT_RECORD_MESSAGE);
    return new McpToolError('corrupt_record', CORRUPT_RECORD_MESSAGE, false);
  }
  // Another call of the same identity holds a store lock (outbox, admission, settings) past the wait.
  for (let c: unknown = e, depth = 0; c instanceof Error && depth < 8; c = c.cause, depth++) {
    if (c instanceof ACEError && c.code === 'lock_busy') return new McpToolError('busy', BUSY_MESSAGE, true);
  }
  if (e instanceof ACEError) {
    // The relay accepts each auth signature once; an identical request in the same second (409
    // `replay`, after the SDK's own retry) clears once the timestamp moves on.
    if (e.code === 'relay_rejected' && e.relayCode === 'replay') {
      return new McpToolError('rate_limited', 'identical request within the same second; retry in 1 s', true);
    }
    // ACEError.message is "<code>: <detail>"; keep only the detail so the result text is not doubled.
    const prefix = `${e.code}: `;
    const message = e.message.startsWith(prefix) ? e.message.slice(prefix.length) : e.message;
    return new McpToolError(e.code, message, e.isTransient);
  }
  return new McpToolError('internal', 'internal error', false);
}

// A type alias (not an interface) so it is assignable to the MCP SDK's index-signature CallToolResult.
export type ToolErrorResult = {
  isError: true;
  content: Array<{ type: 'text'; text: string }>;
  structuredContent: { error: string; message: string; retryable: boolean };
};

export function toolErrorResult(e: McpToolError): ToolErrorResult {
  return {
    isError: true,
    content: [{ type: 'text', text: `${e.code}: ${e.message}` }],
    structuredContent: { error: e.code, message: e.message, retryable: e.retryable },
  };
}
