// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { delegateFailureText, delegateResponseFailureText, deviceRelayFailureText, shortCodeFailureText } from './delegate-failure-text';

const changedRequest = "This request changed after you opened it, so OpenKey didn't approve it. Return to the app or command and start again.";
const approvalCannotProceed = "Couldn't approve this request. Try again.";

const mappedCodes: Array<[string, string]> = [
  ['session_required', 'Your OpenKey session ended. Sign in again, then approve the request again.'],
  ['approval_in_progress', 'This request is already being approved. Wait a moment.'],
  ...[
    'handoff_expired', 'handoff_consumed', 'handoff_replayed', 'handoff_cancelled', 'handoff_not_found',
    'handoff_claimed', 'prepared_expired', 'expired_request', 'expired_result', 'already_approved',
  ].map((code) => [code, 'This request has already been answered or has ended. Return to the app or command and start a new one.'] as [string, string]),
  ...[
    'key-mismatch', 'user-mismatch', 'host-mismatch', 'space-mismatch', 'jwk-mismatch', 'baseline-digest-mismatch',
    'immutable-fields-changed', 'prepared_metadata_mismatch', 'prepared_siwe_mismatch',
    'selected_actions_missing_siwe_entries', 'selected_actions_exceed_siwe_entries', 'invalid_selected_action_ids',
    'handoff-mismatch', 'binding_mismatch', 'request_binding', 'signature-mismatch', 'bound_siwe_parse_failed',
    'authorization_context_failed', 'missing_authorization_context_token', 'missing_prepared',
    'authorization_context_missing_original_siwe',
  ].map((code) => [code, changedRequest] as [string, string]),
  ...[
    'app_key_grant_refused', 'key_delete_not_grantable', 'invalid_siwe_recap', 'invalid_permissions',
  ].map((code) => [code, "OpenKey can't approve this kind of access. The app or command needs to ask for something different."] as [string, string]),
  ['rate_limited', 'Too many attempts. Wait five minutes, then try again.'],
  ...['key_not_found', 'key_state_invalid'].map((code) => [code, "This key isn't available on your account. Choose a key you own and try again."] as [string, string]),
];

const permissionCodes = [
  'candidate-broadens-baseline', 'action-not-in-baseline', 'action-not-in-initial-selection',
  'required-action-missing', 'empty_selection',
];
const expiryCodes = [
  'invalid_expiry', 'invalid_expiration_time', 'missing_expiration_time',
  'expiry_exceeds_link', 'expiry_exceeds_handoff', 'expiry_not_changeable',
];

describe('delegateFailureText code mappings', () => {
  test.each(mappedCodes)('maps %s to its exact message', (code: string, message: string) => {
    expect(delegateResponseFailureText(400, code)).toBe(message);
  });

  test.each(
    permissionCodes.flatMap((code) => [[code, true], [code, false]] as Array<[string, boolean]>),
  )('maps permission code %s for editable=%s', (code: string, visible: boolean) => {
    expect(delegateResponseFailureText(400, code, { permissionsEditable: visible })).toBe(
      visible
        ? "These permissions can't be approved as chosen. Change your selection and approve again."
        : changedRequest,
    );
  });

  test.each(
    expiryCodes.flatMap((code) => [[code, true], [code, false]] as Array<[string, boolean]>),
  )('maps expiry code %s for Change-visible=%s', (code: string, visible: boolean) => {
    expect(delegateResponseFailureText(400, code, { expiryChangeable: visible })).toBe(
      visible
        ? "This access length can't be used. Choose a different one, or start again from the app or command."
        : "This access length can't be used. Start again from the app or command.",
    );
  });

  test('maps HTTP 401 and 429, and keeps busy and ended status precedence', () => {
    expect(delegateResponseFailureText(401, undefined)).toBe(
      'Your OpenKey session ended. Sign in again, then approve the request again.',
    );
    expect(delegateResponseFailureText(429, undefined)).toBe(
      'Too many attempts. Wait five minutes, then try again.',
    );
    expect(delegateResponseFailureText(409, 'session_required')).toBe(
      'This request is already being approved. Wait a moment.',
    );
    expect(delegateResponseFailureText(410, 'key-mismatch')).toBe(
      'This request has already been answered or has ended. Return to the app or command and start a new one.',
    );
    expect(delegateResponseFailureText(410, undefined)).toBe(
      'This request has already been answered or has ended. Return to the app or command and start a new one.',
    );
  });

  test('formats coded, uncoded, and unsafe-code fallback text', () => {
    expect(delegateResponseFailureText(503, 'some_code')).toBe(
      `${approvalCannotProceed} (Error 503 · some_code)`,
    );
    expect(delegateResponseFailureText(500, undefined)).toBe(
      `${approvalCannotProceed} (Error 500)`,
    );
    for (const code of ['free text', 'x'.repeat(65), {}, 10, ''] as unknown[]) {
      expect(delegateResponseFailureText(500, code)).toBe(`${approvalCannotProceed} (Error 500)`);
    }
  });

  test.each([
    [new TypeError('Failed to fetch'), 'Failed to fetch'],
    [new Error('Service refused this request because private server detail'), 'private server detail'],
    ['raw thrown string', 'raw thrown string'],
    [{ status: 503, code: 'some_code' }, 'some_code'],
  ] as Array<[unknown, string]>)('hides non-response failure details', (cause: unknown, rawText: string) => {
    const message = delegateFailureText(cause);
    expect(message).toBe("Couldn't approve this request. Try again.");
    expect(message).not.toContain(rawText);
    expect(message).not.toContain('Delegation');
  });

});

describe('shortCodeFailureText', () => {
  test('formats coded, status-only, and no-status failures exactly', () => {
    expect(shortCodeFailureText(503, 'some_code')).toBe(
      "Couldn't create a short code. Use the full delegation code instead. (Error 503 · some_code)",
    );
    expect(shortCodeFailureText(500)).toBe(
      "Couldn't create a short code. Use the full delegation code instead. (Error 500)",
    );
    expect(shortCodeFailureText()).toBe(
      "Couldn't create a short code. Use the full delegation code instead.",
    );
  });
});
test('formats device relay delivery failures without server text', () => {
  const prefix = "You approved this, but OpenKey couldn't send it to the app or command. Press Approve to try again.";
  expect(deviceRelayFailureText(503, 'some_code')).toBe(`${prefix} (Error 503 · some_code)`);
  expect(deviceRelayFailureText(500)).toBe(`${prefix} (Error 500)`);
  expect(deviceRelayFailureText(null)).toBe(prefix);
  for (const code of ['has spaces', 'x'.repeat(65), {}]) {
    expect(deviceRelayFailureText(500, code)).toBe(`${prefix} (Error 500)`);
  }
});
