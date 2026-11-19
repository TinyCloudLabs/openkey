// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { delegateFailureDetail, delegateFailureText, delegateResponseFailureText, deviceRelayFailureText, isTerminalApprovalFailure, OwnerMessageError, refusalIgnoresKeyChoice, shortCodeFailureText, walletMismatchFailureText } from './delegate-failure-text';

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
    'host-mismatch', 'space-mismatch', 'jwk-mismatch', 'baseline-digest-mismatch',
    'immutable-fields-changed', 'prepared_metadata_mismatch', 'prepared_siwe_mismatch',
    'selected_actions_missing_siwe_entries', 'selected_actions_exceed_siwe_entries', 'invalid_selected_action_ids',
    'handoff-mismatch', 'binding_mismatch', 'request_binding', 'signature-mismatch', 'bound_siwe_parse_failed',
    'authorization_context_failed', 'missing_authorization_context_token', 'missing_prepared',
    'authorization_context_missing_original_siwe',
  ].map((code) => [code, changedRequest] as [string, string]),
  ['key-mismatch', "This request was prepared for a different key than the one you're approving with, so OpenKey didn't approve it. Return to the app or command and start again."],
  ['user-mismatch', "This request was made for a different OpenKey account than the one you're signed in to, so OpenKey didn't approve it. Sign in with the account it was made for, or start again from the app or command."],
  ...[
    'app_key_grant_refused', 'invalid_permissions',
  ].map((code) => [code, "OpenKey can't approve this kind of access. The app or command needs to ask for something different."] as [string, string]),
  ['key_delete_not_grantable', "Apps and commands can't be given permission to delete keys. Nothing was approved. Ask the app or command to send a new request without that permission."],
  ['invalid_siwe_recap', "This request's permission list can't be read. Nothing was approved. Ask the app or command to send a new request."],
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

const terminalCodes = [
  'handoff_expired', 'handoff_consumed', 'handoff_replayed', 'handoff_cancelled', 'handoff_not_found',
  'handoff_claimed', 'prepared_expired', 'expired_request', 'expired_result', 'already_approved',
  'key-mismatch', 'user-mismatch', 'host-mismatch', 'space-mismatch', 'jwk-mismatch', 'baseline-digest-mismatch',
  'immutable-fields-changed', 'prepared_metadata_mismatch', 'prepared_siwe_mismatch',
  'selected_actions_missing_siwe_entries', 'selected_actions_exceed_siwe_entries', 'invalid_selected_action_ids',
  'handoff-mismatch', 'binding_mismatch', 'request_binding', 'signature-mismatch', 'bound_siwe_parse_failed',
  'authorization_context_failed', 'missing_authorization_context_token', 'missing_prepared',
  'authorization_context_missing_original_siwe',
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
    for (const code of ['free text', 'x'.repeat(65), {}, 10, '', 'some_code\n'] as unknown[]) {
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
  test('shows only explicitly tagged owner messages', () => {
    expect(delegateFailureText(new OwnerMessageError('This approval link is incomplete.'))).toBe('This approval link is incomplete.');
    expect(delegateFailureText(new Error('server errorDescription: private detail'))).toBe(approvalCannotProceed);
    expect(delegateFailureText('raw thrown value')).toBe(approvalCannotProceed);
  });
  test.each(terminalCodes)('marks terminal code %s', (code: string) => {
    expect(isTerminalApprovalFailure(400, code)).toBe(true);
  });

  test.each([400, 403])('marks key_delete_not_grantable and invalid_siwe_recap terminal for HTTP %i', (status: number) => {
    expect(isTerminalApprovalFailure(status, 'key_delete_not_grantable')).toBe(true);
    expect(isTerminalApprovalFailure(status, 'invalid_siwe_recap')).toBe(true);
  });

  test('marks HTTP 410 terminal and keeps all non-B/C failures enabled', () => {
    expect(isTerminalApprovalFailure(410, undefined)).toBe(true);
    for (const [status, code] of [
      [409, 'approval_in_progress'], [401, 'session_required'],
      [400, 'candidate-broadens-baseline'], [400, 'invalid_expiry'],
      [403, 'app_key_grant_refused'], [429, 'rate_limited'],
      [404, 'key_not_found'], [500, 'unknown_code'], [500, undefined],
      [400, 'has spaces'], [400, 'x'.repeat(65)], [400, {}],
    ] as Array<[number, unknown]>) {
      expect(isTerminalApprovalFailure(status, code)).toBe(false);
    }
    expect(isTerminalApprovalFailure(400, new Error('key-mismatch'))).toBe(false);
    expect(isTerminalApprovalFailure(400, new OwnerMessageError('owner copy'))).toBe(false);
  });
  test.each([
    'handoff_expired', 'handoff_consumed', 'handoff_replayed', 'handoff_cancelled', 'handoff_not_found',
    'handoff_claimed', 'prepared_expired', 'expired_request', 'expired_result', 'already_approved',
    'user-mismatch', 'request_binding', 'key_delete_not_grantable', 'invalid_siwe_recap',
  ])('a refusal with code %s is the same whichever key is chosen', (code: string) => {
    expect(refusalIgnoresKeyChoice(400, code)).toBe(true);
    expect(refusalIgnoresKeyChoice(403, code)).toBe(true);
  });

  test('HTTP 410 is the same whichever key is chosen', () => {
    expect(refusalIgnoresKeyChoice(410, undefined)).toBe(true);
  });

  test.each([
    'key-mismatch', 'signature-mismatch', 'space-mismatch', 'authorization_context_failed',
    'host-mismatch', 'jwk-mismatch', 'baseline-digest-mismatch', 'immutable-fields-changed',
    'prepared_metadata_mismatch', 'prepared_siwe_mismatch', 'binding_mismatch', 'handoff-mismatch',
    'invalid_permissions', 'app_key_grant_refused', 'key_not_found', 'key_state_invalid',
    'invalid_expiry', 'rate_limited', 'session_required', 'approval_in_progress', 'unknown_code',
  ])('a refusal with code %s can end differently with another key', (code: string) => {
    expect(refusalIgnoresKeyChoice(400, code)).toBe(false);
  });

  test('a refusal with no readable code and a non-ended status keeps the list', () => {
    for (const [status, code] of [[500, undefined], [404, undefined], [400, 'has spaces'], [400, {}]] as Array<[number, unknown]>) {
      expect(refusalIgnoresKeyChoice(status, code)).toBe(false);
    }
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

const genericRefusal = "OpenKey can't approve this kind of access. The app or command needs to ask for something different.";

test('shows the server sentence for app key refusals when present', () => {
  const sentence = "This website doesn't list the key this app asked for, so OpenKey didn't approve it.";
  expect(delegateResponseFailureText(403, 'app_key_grant_refused', { serverMessage: sentence })).toBe(sentence);
  expect(delegateResponseFailureText(403, 'app_key_grant_refused')).toBe(genericRefusal);
  expect(delegateResponseFailureText(403, 'app_key_grant_refused', { serverMessage: '' })).toBe(genericRefusal);
});

test('keeps the server message off the main line for invalid permissions', () => {
  expect(delegateResponseFailureText(400, 'invalid_permissions', { serverMessage: 'Requested spaces must belong to the signing account' }))
    .toBe(genericRefusal);
  expect(delegateResponseFailureText(400, 'invalid_permissions')).toBe(genericRefusal);
});

test('delegateFailureDetail returns the capped message only for 400 invalid_permissions', () => {
  const msg = 'Requested spaces must belong to the signing account';
  expect(delegateFailureDetail(400, 'invalid_permissions', msg)).toBe(msg);
  expect(delegateFailureDetail(400, 'invalid_permissions', 'x'.repeat(500))).toBe('x'.repeat(300));
  expect(delegateFailureDetail(400, 'invalid_permissions', undefined)).toBeNull();
  expect(delegateFailureDetail(400, 'invalid_permissions', '')).toBeNull();
  expect(delegateFailureDetail(400, 'invalid_permissions', 42)).toBeNull();
  expect(delegateFailureDetail(403, 'invalid_permissions', msg)).toBeNull();
  expect(delegateFailureDetail(400, 'app_key_grant_refused', msg)).toBeNull();
});

test('caps long server messages and ignores them for other codes', () => {
  const long = 'x'.repeat(500);
  expect(delegateResponseFailureText(403, 'app_key_grant_refused', { serverMessage: long })).toBe('x'.repeat(300));
  expect(delegateResponseFailureText(400, 'key_not_found', { serverMessage: 'ignored' }))
    .toBe("This key isn't available on your account. Choose a key you own and try again.");
  expect(delegateResponseFailureText(400, 'unknown_code', { serverMessage: 'ignored' }))
    .toBe(`${approvalCannotProceed} (Error 400 · unknown_code)`);
});

test('wallet mismatch text names both shortened wallets', () => {
  expect(walletMismatchFailureText(
    '0xd559aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf412',
    '0x1234bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb9abc',
  )).toBe(
    'This request is for wallet 0xd559…f412, but the key you picked is for 0x1234…9abc. Choose a key for 0xd559…f412, or ask the app or command for a new request. Nothing was approved.',
  );
});

test('other invalid_permissions failures keep the generic line', () => {
  const generic = "OpenKey can't approve this kind of access. The app or command needs to ask for something different.";
  expect(delegateResponseFailureText(400, 'invalid_permissions')).toBe(generic);
  expect(delegateResponseFailureText(400, 'invalid_permissions', { permissionsEditable: true })).toBe(generic);
});
