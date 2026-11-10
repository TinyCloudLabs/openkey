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

export interface DelegateFailureTextOptions {
  permissionsEditable?: boolean;
  expiryChangeable?: boolean;
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
  'key-mismatch': CHANGED_MESSAGE,
  'user-mismatch': CHANGED_MESSAGE,
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
  key_delete_not_grantable: "OpenKey can't approve this kind of access. The app or command needs to ask for something different.",
  invalid_siwe_recap: "OpenKey can't approve this kind of access. The app or command needs to ask for something different.",
  invalid_permissions: "OpenKey can't approve this kind of access. The app or command needs to ask for something different.",
  rate_limited: RATE_LIMITED_MESSAGE,
  key_not_found: "This key isn't available on your account. Choose a key you own and try again.",
  key_state_invalid: "This key isn't available on your account. Choose a key you own and try again.",
};

function safeCode(code: unknown): string | null {
  return typeof code === 'string' && SAFE_CODE.test(code) ? code : null;
}

export function delegateFailureText(
  cause: unknown,
  options: DelegateFailureTextOptions = {},
): string {
  if (typeof cause === 'object' && cause !== null && 'status' in cause) {
    const { status, code } = cause as { status: number; code: unknown };
    if (status === 409) return APPROVAL_BUSY_MESSAGE;
    if (status === 410) return ENDED_MESSAGE;
    if (status === 401) return SESSION_ENDED_MESSAGE;
    if (status === 429) return RATE_LIMITED_MESSAGE;

    const codeText = safeCode(code);
    const mappedMessage = codeText ? CODE_MESSAGES[codeText] : undefined;
    if (typeof mappedMessage === 'function') return mappedMessage(options);
    if (mappedMessage) return mappedMessage;

    return codeText
      ? `Couldn't approve this request. Try again. (Error ${status} · ${codeText})`
      : `Couldn't approve this request. Try again. (Error ${status})`;
  }
  if (cause instanceof Error) return cause.message;
  return 'Delegation failed';
}

export function shortCodeFailureText(status?: number, code?: unknown): string {
  if (status === undefined) return SHORT_CODE_FAILURE;
  const codeText = safeCode(code);
  return codeText
    ? `${SHORT_CODE_FAILURE} (Error ${status} · ${codeText})`
    : `${SHORT_CODE_FAILURE} (Error ${status})`;
}
