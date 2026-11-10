// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { delegateFailureText, shortCodeFailureText } from './delegate-failure-text';

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
    expect(delegateFailureText({ status: 400, code })).toBe(message);
  });

  test.each(
    permissionCodes.flatMap((code) => [[code, true], [code, false]] as Array<[string, boolean]>),
  )('maps permission code %s for editable=%s', (code: string, visible: boolean) => {
    expect(delegateFailureText({ status: 400, code }, { permissionsEditable: visible })).toBe(
      visible
        ? "These permissions can't be approved as chosen. Change your selection and approve again."
        : changedRequest,
    );
  });

  test.each(
    expiryCodes.flatMap((code) => [[code, true], [code, false]] as Array<[string, boolean]>),
  )('maps expiry code %s for Change-visible=%s', (code: string, visible: boolean) => {
    expect(delegateFailureText({ status: 400, code }, { expiryChangeable: visible })).toBe(
      visible
        ? "This access length can't be used. Choose a different one, or start again from the app or command."
        : "This access length can't be used. Start again from the app or command.",
    );
  });

  test('maps HTTP 401 and 429, and keeps busy and ended status precedence', () => {
    expect(delegateFailureText({ status: 401, code: undefined })).toBe(
      'Your OpenKey session ended. Sign in again, then approve the request again.',
    );
    expect(delegateFailureText({ status: 429, code: undefined })).toBe(
      'Too many attempts. Wait five minutes, then try again.',
    );
    expect(delegateFailureText({ status: 409, code: 'session_required' })).toBe(
      'This request is already being approved. Wait a moment.',
    );
    expect(delegateFailureText({ status: 410, code: 'key-mismatch' })).toBe(
      'This request has already been answered or has ended. Return to the app or command and start a new one.',
    );
    expect(delegateFailureText({ status: 410, code: undefined })).toBe(
      'This request has already been answered or has ended. Return to the app or command and start a new one.',
    );
  });

  test('formats coded, uncoded, and unsafe-code fallback text', () => {
    expect(delegateFailureText({ status: 503, code: 'some_code' })).toBe(
      `${approvalCannotProceed} (Error 503 · some_code)`,
    );
    expect(delegateFailureText({ status: 500, code: undefined })).toBe(
      `${approvalCannotProceed} (Error 500)`,
    );
    for (const code of ['free text', 'x'.repeat(65), {}, 10, ''] as unknown[]) {
      expect(delegateFailureText({ status: 500, code })).toBe(`${approvalCannotProceed} (Error 500)`);
    }
  });

  test('keeps a plain Error message unchanged', () => {
    expect(delegateFailureText(new Error('wallet failed'))).toBe('wallet failed');
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
