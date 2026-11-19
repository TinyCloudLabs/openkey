// TC-3441: a 409 is read by its code before its status, and the two codes that
// had no sentence read as the permission-request refusal.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { delegateResponseFailureText } from './delegate-failure-text';

const busy = 'This request is already being approved. Wait a moment.';
const changedRequest = "This request changed after you opened it, so OpenKey didn't approve it. Return to the app or command and start again.";
const notApprovable = "OpenKey can't approve this kind of access. The app or command needs to ask for something different.";

describe('HTTP 409', () => {
  test.each([undefined, 'approval_in_progress', 'handoff_signing', 'session_required', 'unknown_code', 'constructor', '__proto__'])(
    'still reads as busy with code %s',
    (code: string | undefined) => {
      expect(delegateResponseFailureText(409, code)).toBe(busy);
    },
  );

  test('another account approving does not read as busy', () => {
    expect(delegateResponseFailureText(409, 'request_binding')).toBe(changedRequest);
  });

  test('an already signed renewal does not read as busy', () => {
    const text = delegateResponseFailureText(409, 'renewal_already_signed');
    expect(text).not.toContain('Wait a moment');
    expect(text).toBe("Couldn't approve this request. Try again. (Error 409 · renewal_already_signed)");
  });
});

describe('codes that had no sentence', () => {
  test.each(['delegation_prepare_failed', 'signed_exceeds_request'])('%s reads as the permission-request refusal', (code: string) => {
    expect(delegateResponseFailureText(400, code)).toBe(notApprovable);
  });

  test('invalid_permissions keeps its sentence', () => {
    expect(delegateResponseFailureText(400, 'invalid_permissions')).toBe(notApprovable);
  });
});
