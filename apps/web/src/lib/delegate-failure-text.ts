import { apiBusyOrEndedMessage } from './api-busy-or-ended';

const SAFE_CODE = /^[A-Za-z0-9_-]{1,64}$/;
const ENDED_MESSAGE = 'This request has already been answered or has ended. Return to the app or command and start a new one.';
const CHANGED_MESSAGE = "This request changed after you opened it, so OpenKey didn't approve it. Return to the app or command and start again.";
const PERMISSIONS_EDITABLE_MESSAGE = "These permissions can't be approved as chosen. Change your selection and approve again.";
const EXPIRY_CHANGEABLE_MESSAGE = "This access length can't be used. Choose a different one, or start again from the app or command.";
const EXPIRY_NOT_CHANGEABLE_MESSAGE = "This access length can't be used. Start again from the app or command.";
const SESSION_ENDED_MESSAGE = 'Your OpenKey session ended. Sign in again, then approve the request again.';
const RATE_LIMITED_MESSAGE = 'Too many attempts. Wait five minutes, then try again.';
const SHORT_CODE_FAILURE = "Couldn't create a short code. Use the full delegation code instead.";
const APPROVAL_BUSY_MESSAGE = apiBusyOrEndedMessage(409) ?? 'This request is already being approved. Wait a moment.';
const APPROVAL_FAILURE_MESSAGE = "Couldn't approve this request. Try again.";

export interface DelegateFailureTextOptions {
  permissionsEditable?: boolean;
  expiryChangeable?: boolean;
  serverMessage?: string;
}

const SERVER_MESSAGE_MAX = 300;

export function delegateServerMessage(body: unknown): string | undefined {
  const message = (body as { message?: unknown } | null)?.message;
  return typeof message === 'string' && message.trim() ? message.slice(0, SERVER_MESSAGE_MAX) : undefined;
}

export function delegateFailureDetail(status: number, code: unknown, serverMessage: unknown): string | null {
  if (status !== 400 || code !== 'invalid_permissions') return null;
  return delegateServerMessage({ message: serverMessage }) ?? null;
}

type MappedMessage = string | ((options: DelegateFailureTextOptions) => string);

const CODE_MESSAGES: Record<string, MappedMessage> = {
  session_required: SESSION_ENDED_MESSAGE,
  approval_in_progress: APPROVAL_BUSY_MESSAGE,
  handoff_expired: ENDED_MESSAGE,
  handoff_consumed: ENDED_MESSAGE,
  handoff_replayed: ENDED_MESSAGE,
  handoff_cancelled: ENDED_MESSAGE,
  handoff_not_found: ENDED_MESSAGE,
  handoff_claimed: ENDED_MESSAGE,
  prepared_expired: ENDED_MESSAGE,
  expired_request: ENDED_MESSAGE,
  expired_result: ENDED_MESSAGE,
  already_approved: ENDED_MESSAGE,
  'key-mismatch': "This request was prepared for a different key than the one you're approving with, so OpenKey didn't approve it. Return to the app or command and start again.",
  'user-mismatch': "This request was made for a different OpenKey account than the one you're signed in to, so OpenKey didn't approve it. Sign in with the account it was made for, or start again from the app or command.",
  'host-mismatch': CHANGED_MESSAGE,
  'space-mismatch': CHANGED_MESSAGE,
  'jwk-mismatch': CHANGED_MESSAGE,
  'baseline-digest-mismatch': CHANGED_MESSAGE,
  'immutable-fields-changed': CHANGED_MESSAGE,
  prepared_metadata_mismatch: CHANGED_MESSAGE,
  prepared_siwe_mismatch: CHANGED_MESSAGE,
  selected_actions_missing_siwe_entries: CHANGED_MESSAGE,
  selected_actions_exceed_siwe_entries: CHANGED_MESSAGE,
  invalid_selected_action_ids: CHANGED_MESSAGE,
  'handoff-mismatch': CHANGED_MESSAGE,
  binding_mismatch: CHANGED_MESSAGE,
  request_binding: CHANGED_MESSAGE,
  'signature-mismatch': CHANGED_MESSAGE,
  bound_siwe_parse_failed: CHANGED_MESSAGE,
  authorization_context_failed: CHANGED_MESSAGE,
  missing_authorization_context_token: CHANGED_MESSAGE,
  missing_prepared: CHANGED_MESSAGE,
  authorization_context_missing_original_siwe: CHANGED_MESSAGE,
  'candidate-broadens-baseline': (options) => options.permissionsEditable ? PERMISSIONS_EDITABLE_MESSAGE : CHANGED_MESSAGE,
  'action-not-in-baseline': (options) => options.permissionsEditable ? PERMISSIONS_EDITABLE_MESSAGE : CHANGED_MESSAGE,
  'action-not-in-initial-selection': (options) => options.permissionsEditable ? PERMISSIONS_EDITABLE_MESSAGE : CHANGED_MESSAGE,
  'required-action-missing': (options) => options.permissionsEditable ? PERMISSIONS_EDITABLE_MESSAGE : CHANGED_MESSAGE,
  empty_selection: (options) => options.permissionsEditable ? PERMISSIONS_EDITABLE_MESSAGE : CHANGED_MESSAGE,
  invalid_expiry: (options) => options.expiryChangeable ? EXPIRY_CHANGEABLE_MESSAGE : EXPIRY_NOT_CHANGEABLE_MESSAGE,
  invalid_expiration_time: (options) => options.expiryChangeable ? EXPIRY_CHANGEABLE_MESSAGE : EXPIRY_NOT_CHANGEABLE_MESSAGE,
  missing_expiration_time: (options) => options.expiryChangeable ? EXPIRY_CHANGEABLE_MESSAGE : EXPIRY_NOT_CHANGEABLE_MESSAGE,
  expiry_exceeds_link: (options) => options.expiryChangeable ? EXPIRY_CHANGEABLE_MESSAGE : EXPIRY_NOT_CHANGEABLE_MESSAGE,
  expiry_exceeds_handoff: (options) => options.expiryChangeable ? EXPIRY_CHANGEABLE_MESSAGE : EXPIRY_NOT_CHANGEABLE_MESSAGE,
  expiry_not_changeable: (options) => options.expiryChangeable ? EXPIRY_CHANGEABLE_MESSAGE : EXPIRY_NOT_CHANGEABLE_MESSAGE,
  app_key_grant_refused: "OpenKey can't approve this kind of access. The app or command needs to ask for something different.",
  key_delete_not_grantable: "Apps and commands can't be given permission to delete keys. Nothing was approved. Ask the app or command to send a new request without that permission.",
  invalid_siwe_recap: "This request's permission list can't be read. Nothing was approved. Ask the app or command to send a new request.",
  invalid_permissions: "OpenKey can't approve this kind of access. The app or command needs to ask for something different.",
  rate_limited: RATE_LIMITED_MESSAGE,
  key_not_found: "This key isn't available on your account. Choose a key you own and try again.",
  key_state_invalid: "This key isn't available on your account. Choose a key you own and try again.",
};

function safeCode(code: unknown): string | null {
  if (typeof code !== 'string') return null;
  const match = SAFE_CODE.exec(code);
  return match?.[0] === code ? code : null;
}

const TERMINAL_APPROVAL_CODES: Record<string, true> = {
  handoff_expired: true,
  handoff_consumed: true,
  handoff_replayed: true,
  handoff_cancelled: true,
  handoff_not_found: true,
  handoff_claimed: true,
  prepared_expired: true,
  expired_request: true,
  expired_result: true,
  already_approved: true,
  'key-mismatch': true,
  'user-mismatch': true,
  'host-mismatch': true,
  'space-mismatch': true,
  'jwk-mismatch': true,
  'baseline-digest-mismatch': true,
  'immutable-fields-changed': true,
  prepared_metadata_mismatch: true,
  prepared_siwe_mismatch: true,
  selected_actions_missing_siwe_entries: true,
  selected_actions_exceed_siwe_entries: true,
  invalid_selected_action_ids: true,
  key_delete_not_grantable: true,
  invalid_siwe_recap: true,
  'handoff-mismatch': true,
  binding_mismatch: true,
  request_binding: true,
  'signature-mismatch': true,
  bound_siwe_parse_failed: true,
  authorization_context_failed: true,
  missing_authorization_context_token: true,
  missing_prepared: true,
  authorization_context_missing_original_siwe: true,
};

export function isTerminalApprovalFailure(status: number, code: unknown): boolean {
  const codeText = safeCode(code);
  return status === 410 || (codeText !== null && TERMINAL_APPROVAL_CODES[codeText] === true);
}


export class OwnerMessageError extends Error {}

export function delegateFailureText(cause: unknown): string {
  return cause instanceof OwnerMessageError ? cause.message : APPROVAL_FAILURE_MESSAGE;
}

function shortWallet(address: string): string {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export function walletMismatchFailureText(expected: string, picked: string): string {
  const wanted = shortWallet(expected);
  return `This request is for wallet ${wanted}, but the key you picked is for ${shortWallet(picked)}. Choose a key for ${wanted}, or ask the app or command for a new request. Nothing was approved.`;
}

export function delegateResponseFailureText(
  status: number,
  code: unknown,
  options: DelegateFailureTextOptions = {},
): string {
  if (status === 409) return APPROVAL_BUSY_MESSAGE;
  if (status === 410) return ENDED_MESSAGE;
  if (status === 401) return SESSION_ENDED_MESSAGE;
  if (status === 429) return RATE_LIMITED_MESSAGE;

  const codeText = safeCode(code);
  const serverMessage = delegateServerMessage({ message: options.serverMessage });
  if (serverMessage && codeText === 'app_key_grant_refused') return serverMessage;
  const mappedMessage = codeText ? CODE_MESSAGES[codeText] : undefined;
  if (typeof mappedMessage === 'function') return mappedMessage(options);
  if (mappedMessage) return mappedMessage;

  return codeText
    ? `${APPROVAL_FAILURE_MESSAGE} (Error ${status} · ${codeText})`
    : `${APPROVAL_FAILURE_MESSAGE} (Error ${status})`;
}

export class DeviceRelayDeliveryError {
  readonly code: string | null;

  constructor(readonly status: number | null, code: unknown) {
    this.code = safeCode(code);
  }
}

export function deviceRelayFailureText(status: number | null, code?: unknown): string {
  const prefix = "You approved this, but OpenKey couldn't send it to the app or command. Press Approve to try again.";
  if (status === null) return prefix;
  const codeText = safeCode(code);
  return codeText ? `${prefix} (Error ${status} · ${codeText})` : `${prefix} (Error ${status})`;
}

export function shortCodeFailureText(status?: number, code?: unknown): string {
  if (status === undefined) return SHORT_CODE_FAILURE;
  const codeText = safeCode(code);
  return codeText
    ? `${SHORT_CODE_FAILURE} (Error ${status} · ${codeText})`
    : `${SHORT_CODE_FAILURE} (Error ${status})`;
}
