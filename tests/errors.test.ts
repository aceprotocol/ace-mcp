import { describe, it, expect } from 'vitest';
import { ACEError } from '@ace-protocol/sdk';
import { McpToolError, toolErrorFromACE, toolErrorResult } from '../src/errors.js';
import { SealedDataError } from '../src/identity/kek.js';

describe('tool errors', () => {
  it('maps a timed-out per-identity lock wait to retryable busy, also when wrapped', () => {
    const held = new ACEError('lock_busy', "lock 'threads' is held");
    expect(toolErrorFromACE(held)).toMatchObject({ code: 'busy', retryable: true, message: 'another call for this identity is in progress; retry' });
    expect(toolErrorFromACE(new ACEError('storage_failed', 'thread update failed', { cause: held }))).toMatchObject({ code: 'busy', retryable: true });
    expect(toolErrorFromACE(new ACEError('storage_failed', 'write failed'))).toMatchObject({ code: 'storage_failed', retryable: true });
  });
  it('maps the key event log codes by their SDK category', () => {
    for (const code of ['invalid_kel', 'kel_conflict', 'unknown_prekey'] as const) {
      expect(toolErrorFromACE(new ACEError(code, 'x'))).toMatchObject({ code, retryable: false, message: 'x' });
    }
    expect(toolErrorFromACE(new ACEError('identity_unavailable', 'x'))).toMatchObject({ code: 'identity_unavailable', retryable: true });
  });
  it('maps transient SDK errors to retryable and permanent ones to not retryable', () => {
    expect(toolErrorFromACE(new ACEError('relay_unavailable', 'down'))).toMatchObject({ code: 'relay_unavailable', retryable: true });
    expect(toolErrorFromACE(new ACEError('receiver_capacity', 'full'))).toMatchObject({ code: 'receiver_capacity', retryable: true });
    expect(toolErrorFromACE(new ACEError('transition_not_allowed', 'no'))).toMatchObject({ code: 'transition_not_allowed', retryable: false });
    expect(toolErrorFromACE(new Error('boom'))).toMatchObject({ code: 'internal', retryable: false });
  });
  it('strips the "<code>: " prefix ACEError puts on its message', () => {
    expect(toolErrorFromACE(new ACEError('unknown_peer', 'no such agent')).message).toBe('no such agent');
    expect(toolErrorResult(toolErrorFromACE(new ACEError('unknown_peer', 'no such agent'))).content[0].text).toBe('unknown_peer: no such agent');
    expect(toolErrorFromACE(new ACEError('unknown_peer')).message).toBe('unknown_peer');
  });
  it('maps an undecryptable record to corrupt_record (not retryable), also when the SDK wrapped it, and logs where', () => {
    const logged: object[] = [];
    const logger = { error: (o: object) => { logged.push(o); } };
    const sealed = new SealedDataError('sealed blob could not be decrypted', { aceId: 'ace:x', key: 'threads/t.json' });
    expect(toolErrorFromACE(sealed, logger)).toMatchObject({ code: 'corrupt_record', retryable: false, message: 'a stored record could not be decrypted' });
    const wrapped = new ACEError('storage_failed', 'thread load failed', { cause: sealed });
    expect(toolErrorFromACE(wrapped, logger)).toMatchObject({ code: 'corrupt_record', retryable: false });
    expect(logged).toEqual([{ code: 'corrupt_record', aceId: 'ace:x', key: 'threads/t.json' }, { code: 'corrupt_record', aceId: 'ace:x', key: 'threads/t.json' }]);
    expect(toolErrorFromACE(new ACEError('storage_failed', 'down'))).toMatchObject({ code: 'storage_failed', retryable: true });
  });
  it('maps a relay 409 replay to retryable rate_limited (other relay rejections stay as they are)', () => {
    // As sdk-ts relay.ts errorFor() builds it for HTTP 409 {"error":"replay"}.
    const replay = new ACEError('relay_rejected', 'HTTP 409 replay: duplicate signature', { status: 409, relayCode: 'replay' });
    expect(toolErrorFromACE(replay)).toMatchObject({ code: 'rate_limited', retryable: true, message: 'identical request within the same second; retry in 1 s' });
    const other = new ACEError('relay_rejected', 'HTTP 409 conflict', { status: 409, relayCode: 'conflict' });
    expect(toolErrorFromACE(other)).toMatchObject({ code: 'relay_rejected', retryable: false });
  });
  it('renders the MCP error result shape', () => {
    const r = toolErrorResult(new McpToolError('unauthenticated', 'need a token', false));
    expect(r.isError).toBe(true);
    expect(r.structuredContent).toEqual({ error: 'unauthenticated', message: 'need a token', retryable: false });
    expect(r.content[0]).toEqual({ type: 'text', text: 'unauthenticated: need a token' });
  });
});
