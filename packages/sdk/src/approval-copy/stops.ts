// `stopForSdkError` reads only the `code` of an `OpenKeyError`, so the copy does not depend on the rest of the SDK.
import { SIGN_IN, STOP_PARTS } from './strings';

/** The buttons a stop offers. `STOP_PARTS.buttons` holds each one's label. */
export type StopButton =
  | 'close'
  | 'try-again'
  | 'copy-details'
  | 'switch-account'
  | 'link-wallet'
  | 'choose-another-key'
  | 'start-again'
  | 'enter-code';

/**
 * What the support line is made of. `status`: the HTTP status leads the line. `code`: a fixed code, or `'reply'` for
 * the code the server sent (shown only when it is a safe code). `detail`: the name of one fact the page itself
 * reads from the link or the account (never a server sentence).
 */
export interface StopSupport {
  readonly status: boolean;
  readonly code: string;
  readonly detail?: string;
}

/**
 * One reason the approval cannot go on, or one line next to a control.
 * `page`: nothing on this page can fix it, so a stop page replaces the card. `inline`: the line sits next to the
 * control that fixes it. `sign-in`: the sign-in card with this heading.
 */
export interface Stop {
  readonly placement: 'page' | 'inline' | 'sign-in';
  readonly title: string;
  readonly body: string;
  readonly buttons: readonly StopButton[];
  readonly support: StopSupport | null;
  /** The marker above the heading when it is not `STOP_PARTS.marker`. */
  readonly marker?: string;
  /** A second small line under the body, for one kind of link only. */
  readonly legacyLine?: string;
  /** The title when the requester is known. */
  readonly titleNamed?: string;
  /** The body for a prepared sign-in. */
  readonly bodyPrepared?: string;
  /** The title and body when the address is not a safe web address at all. */
  readonly unsafe?: { readonly title: string; readonly body: string };
  /** The body when the page does not know which wallet the link asked for. */
  readonly bodyUnknownWallet?: string;
}

/** Lines next to the Approve button when the browser wallet cannot sign. */
export interface InlineLines {
  readonly placement: 'inline';
  readonly lines: Readonly<Record<string, string>>;
}

const statusAndReply = { status: true, code: 'reply' } as const;

export const STOPS = {
  S1: {
    placement: 'page',
    title: 'This link is cut off',
    body: 'Part of the approval link is missing. Chat apps and link previews often shorten long links. Ask the app or agent to send it again on its own line, then open it directly, not from a preview.',
    buttons: ['close'],
    support: { status: false, code: 'incomplete_link' },
    /** A second small line for the legacy link only. */
    legacyLine: 'Using TinyCloud CLI? Use version 1.5.0 or later and ask for approval without --paste. That gives a short link.',
  },
  S2: {
    placement: 'page',
    title: 'This browser can’t hold on to the request',
    body: 'OpenKey keeps the request in this tab while you sign in, and this browser blocked that. It happens in private windows and in-app browsers. Open the original link in Safari or Chrome instead.',
    buttons: ['close'],
    support: { status: false, code: 'tab_storage_blocked' },
  },
  S3: {
    placement: 'page',
    title: 'This link is missing its last part',
    body: 'Everything after the # in the link is needed, and it isn’t here. If you opened the link in another tab first, go back to that tab. If not, open the original link from your message again, or ask for a new one sent on its own line.',
    buttons: ['close'],
    support: { status: false, code: 'approval_reference_missing' },
  },
  S4: {
    placement: 'page',
    title: 'This request expired',
    /** With the requester's name. */
    titleNamed: '{requester}’s request expired',
    body: 'Requests stay open for a short time and this one ran out. Ask your agent for a new link.',
    /** Prepared sign-in. */
    bodyPrepared: 'This sign-in was open for 5 minutes and ran out. Run the command again.',
    buttons: ['close'],
    support: statusAndReply,
  },
  S5: {
    placement: 'page',
    title: 'This request can’t be found',
    body: 'It may have expired, or the link may be wrong. Ask the app or agent for a new link.',
    buttons: ['close'],
    support: statusAndReply,
  },
  S6: {
    placement: 'page',
    title: 'Couldn’t load this request',
    body: 'OpenKey’s server didn’t answer. Your link is still good and nothing has changed.',
    buttons: ['try-again', 'close'],
    support: { status: true, code: 'request_load_failed' },
  },
  S7: {
    placement: 'page',
    title: 'This link doesn’t match the request it points to',
    body: 'The details in the link differ from what the requester registered with OpenKey. It may have been edited, or pasted together from two links. Don’t approve a different request in its place. Ask for a fresh link.',
    buttons: ['close'],
    support: statusAndReply,
  },
  S8: {
    placement: 'page',
    title: 'This request names more than one wallet',
    body: 'It asks for data owned by {owners}. One approval can only cover one wallet’s data. Start again from the app or command, one wallet at a time.',
    buttons: ['close'],
    support: { status: false, code: 'owner_conflict', detail: 'owners' },
  },
  S9: {
    placement: 'page',
    title: 'This link would send your approval to a site OpenKey doesn’t know',
    body: 'It asks OpenKey to deliver the approval to {originPath}. OpenKey only delivers to this device or to registered TinyCloud apps, so it refused. If someone sent you this link, don’t use it.',
    buttons: ['close'],
    support: { status: false, code: 'callback_not_registered', detail: 'originPath' },
    /** When the address is not a safe web address at all. */
    unsafe: {
      title: 'This link’s return address isn’t valid',
      body: 'It tells OpenKey to send your approval to an address that isn’t a safe web address, so OpenKey refused. Start again from the app or command.',
    },
  },
  S10: {
    placement: 'page',
    title: 'This link names a node that isn’t valid',
    body: 'A TinyCloud node must be an HTTPS address. Start again from the app or command.',
    buttons: ['close'],
    support: { status: false, code: 'node_invalid', detail: 'host' },
  },
  S11: {
    placement: 'page',
    title: 'OpenKey can’t read what this request asks for',
    body: 'The permission list in this link is damaged, or written in a way this version of OpenKey doesn’t know. OpenKey won’t sign something it can’t show you. Updating the app or CLI and starting again usually fixes it.',
    buttons: ['close', 'copy-details'],
    support: { status: true, code: 'invalid_siwe_recap' },
  },
  S12: {
    placement: 'page',
    title: 'OpenKey doesn’t know this kind of link',
    body: 'It was made by a version of the app or CLI that this OpenKey can’t read. Update it, then start again.',
    buttons: ['close'],
    support: { status: false, code: 'transport_version', detail: 'value' },
  },
  S13: {
    placement: 'page',
    title: 'This request was already answered',
    body: 'It was approved, declined or cancelled, here or in another tab, and each request works once. If your agent is still waiting, ask it for a new link.',
    buttons: ['close'],
    support: statusAndReply,
    marker: STOP_PARTS.markerNew,
  },
  S14: {
    placement: 'page',
    title: 'The request changed while you were reading it',
    body: 'What OpenKey was asked to sign no longer matches what this page showed you, so it stopped. Start again from the app to review the current request.',
    buttons: ['close'],
    support: statusAndReply,
  },
  S15: {
    placement: 'page',
    title: 'This request belongs to another OpenKey account',
    body: 'It was opened with a different account. You’re signed in as {email}. Switch to the account you started with, or start again from the app or command.',
    buttons: ['switch-account', 'close'],
    support: statusAndReply,
  },
  S16: {
    placement: 'page',
    title: 'The key changed partway through',
    body: 'This request was prepared for a different key than the one you approved with, so OpenKey stopped. Start again from the app or command.',
    buttons: ['close'],
    support: { status: true, code: 'key-mismatch' },
  },
  S17: {
    placement: 'page',
    title: 'This request is for a wallet this account doesn’t have',
    body: 'The link asks for data owned by one wallet. You’re signed in as {email}, and none of this account’s keys is that wallet. A key can only share its own data, so there is nothing to approve here yet.',
    /** Prepared sign-in and revoke use the same page without `link-wallet`. */
    buttons: ['switch-account', 'link-wallet'],
    support: { status: false, code: 'wallet_not_on_account', detail: 'wanted' },
  },
  S18: {
    placement: 'page',
    title: 'Wrong key for this request',
    body: 'The link asks for data owned by wallet {wanted}. You chose {keyName}, which is a different wallet. A key can only share its own data, so OpenKey stopped before signing.',
    /** When the page does not know the wallet the link asked for. */
    bodyUnknownWallet: 'This request asks for data owned by another wallet. You chose {keyName}. A key can only share its own data, so OpenKey stopped before signing.',
    buttons: ['choose-another-key', 'start-again'],
    support: { status: true, code: 'invalid_permissions' },
  },
  S19: {
    placement: 'page',
    title: 'The app’s request has a mistake in it',
    body: 'The app asked for something OpenKey can’t approve as written. You didn’t do anything wrong. The app’s developer needs to fix the request.',
    buttons: ['copy-details', 'close'],
    support: statusAndReply,
  },
  S20: {
    placement: 'page',
    title: 'App keys can’t be asked for this way',
    body: 'This request asks for an app’s own key. Those can only be asked for when you sign in on the app’s website, not from a command or a device sign-in. OpenKey refused the whole request.',
    buttons: ['close', 'copy-details'],
    support: { status: true, code: 'app_key_grant_refused' },
  },
  S21: {
    placement: 'page',
    title: 'Apps can’t be given permission to delete keys',
    body: 'This request includes permission to delete your encryption keys. OpenKey never grants that to an app or an agent, so it refused the whole request.',
    buttons: ['close', 'copy-details'],
    support: { status: true, code: 'key_delete_not_grantable' },
  },
  S22: {
    placement: 'sign-in',
    title: SIGN_IN.signedOutPartway.heading,
    body: SIGN_IN.signedOutPartway.line,
    buttons: [],
    support: { status: true, code: 'session_required' },
  },
  S23: {
    placement: 'page',
    title: 'Too many sign-in requests',
    body: 'OpenKey allows 5 sign-in requests in 5 minutes for one account. Wait a few minutes, then run the command again.',
    buttons: ['close'],
    support: { status: true, code: 'rate_limited' },
  },
  S24: {
    placement: 'inline',
    title: 'This request is already being approved',
    body: 'Another tab or a second click got there first. Wait a moment, then press Approve again.',
    buttons: [],
    support: statusAndReply,
  },
  S25: {
    placement: 'page',
    title: 'That key isn’t available any more',
    body: '{keyName} was archived or removed after this page loaded. Choose one of your other keys to continue.',
    buttons: ['choose-another-key'],
    support: { status: true, code: 'key_not_found' },
  },
  S26: {
    placement: 'page',
    title: 'The approval didn’t go through',
    body: 'OpenKey doesn’t have a better explanation yet. Try again. If it happens twice, send us the line below and we’ll find it.',
    buttons: ['try-again', 'close'],
    support: statusAndReply,
  },
  S27: {
    placement: 'page',
    title: 'OpenKey couldn’t finish this request',
    body: 'OpenKey couldn’t read the server’s reply, so nothing was approved. Try again. If it keeps happening, contact the app.',
    buttons: ['try-again', 'close'],
    support: { status: true, code: 'reply_unreadable' },
  },
  S28: {
    placement: 'page',
    title: 'This link doesn’t match the code request',
    body: 'Enter the code from your terminal instead.',
    /** The button goes to /device. */
    buttons: ['enter-code'],
    support: { status: false, code: 'device_link_mismatch' },
  },
  /** Next to Approve when the browser wallet cannot sign. */
  S32: {
    placement: 'inline',
    lines: {
      noWallet: 'No browser wallet found. Open this page in the browser that has your wallet.',
      walletLacks: 'Your wallet doesn’t have {short}. Switch to that account in your wallet, then press Approve.',
      walletDeclined: 'Your wallet turned down the signature. Nothing was approved. Press Approve to try again.',
    },
  },
  /** Under the permission list, for the codes that say the ticked set is not allowed. */
  permissions: {
    placement: 'inline',
    title: '',
    body: 'These permissions can’t be approved as chosen. Change your selection and approve again.',
    buttons: [],
    support: statusAndReply,
  },
  /** Under the length, when the person can pick another one. */
  length: {
    placement: 'inline',
    title: '',
    body: 'This access length can’t be used. Choose a different one, or start again from the app or command.',
    buttons: [],
    support: statusAndReply,
  },
  /** When the access length is fixed by the request. */
  lengthFixed: {
    placement: 'inline',
    title: '',
    body: 'This access length can’t be used. Start again from the app or command.',
    buttons: [],
    support: statusAndReply,
  },
} as const satisfies Record<string, Stop | InlineLines>;

export type StopId = keyof typeof STOPS;

const CHANGED_CODES = [
  'host-mismatch', 'space-mismatch', 'jwk-mismatch', 'baseline-digest-mismatch',
  'immutable-fields-changed', 'prepared_metadata_mismatch', 'prepared_siwe_mismatch',
  'selected_actions_missing_siwe_entries', 'selected_actions_exceed_siwe_entries', 'invalid_selected_action_ids',
  'handoff-mismatch', 'binding_mismatch', 'request_binding', 'signature-mismatch', 'bound_siwe_parse_failed',
  'authorization_context_failed', 'missing_authorization_context_token', 'missing_prepared',
  'authorization_context_missing_original_siwe',
];
const ANSWERED_CODES = [
  'handoff_expired', 'handoff_consumed', 'handoff_replayed', 'handoff_cancelled', 'handoff_not_found',
  'handoff_claimed', 'prepared_expired', 'expired_result', 'already_approved',
];
const EXPIRED_CODES = ['expired', 'expired_request'];
const PERMISSION_CODES = [
  'candidate-broadens-baseline', 'action-not-in-baseline', 'action-not-in-initial-selection',
  'required-action-missing', 'empty_selection',
];
const EXPIRY_CODES = [
  'invalid_expiry', 'invalid_expiration_time', 'missing_expiration_time',
  'expiry_exceeds_link', 'expiry_exceeds_handoff', 'expiry_not_changeable',
];

const BY_CODE: Record<string, StopId> = {
  session_required: 'S22',
  approval_in_progress: 'S24',
  'key-mismatch': 'S16',
  'user-mismatch': 'S15',
  app_key_grant_refused: 'S20',
  key_delete_not_grantable: 'S21',
  invalid_siwe_recap: 'S11',
  invalid_permissions: 'S19',
  delegation_prepare_failed: 'S19',
  signed_exceeds_request: 'S19',
  rate_limited: 'S23',
  key_not_found: 'S25',
  key_state_invalid: 'S25',
  ...Object.fromEntries(CHANGED_CODES.map((code) => [code, 'S14'])),
  ...Object.fromEntries(ANSWERED_CODES.map((code) => [code, 'S13'])),
  ...Object.fromEntries(EXPIRED_CODES.map((code) => [code, 'S4'])),
};

/** The codes `stopForReply` maps to a reason of their own. */
export const KNOWN_REPLY_CODES: readonly string[] = [...Object.keys(BY_CODE), ...PERMISSION_CODES, ...EXPIRY_CODES];

const SAFE_CODE = /^[A-Za-z0-9_-]{1,64}$/;

/** The code when it is short and plain (letters, digits, `_`, `-`), else null. Nothing else is ever shown as a code. */
export function safeCode(code: unknown): string | null {
  return typeof code === 'string' && SAFE_CODE.test(code) ? code : null;
}

export interface ReplyInput {
  /** The HTTP status of the reply. */
  status: number;
  /** The `code` the reply carried, if any. */
  code?: unknown;
  /**
   * `load`: the reply to opening an approval link (404 is S5, a 5xx is S6, 410 is S4, anything else S7).
   * Default `approve`: a reply to preparing or approving.
   */
  phase?: 'approve' | 'load';
  /** The person can change the ticked permissions on this page. */
  permissionsEditable?: boolean;
  /** The person can pick another access length on this page. */
  expiryChangeable?: boolean;
}

/** Which reason a reply from the server means. Every code the delegate pages know has one; anything else is S26. */
export function stopForReply(input: ReplyInput): StopId {
  const { status, phase = 'approve', permissionsEditable = false, expiryChangeable = false } = input;
  const code = safeCode(input.code);
  if (phase === 'load') {
    if (status === 410 || (code !== null && EXPIRED_CODES.includes(code))) return 'S4';
    if (status === 404 || code === 'not_found' || code === 'gone') return 'S5';
    if (status >= 500) return 'S6';
    return 'S7';
  }
  if (status === 401) return 'S22';
  if (status === 409) return 'S24';
  if (status === 429) return 'S23';
  if (code !== null && PERMISSION_CODES.includes(code)) return permissionsEditable ? 'permissions' : 'S14';
  if (code !== null && EXPIRY_CODES.includes(code)) return expiryChangeable ? 'length' : 'lengthFixed';
  if (status === 410 && (code === null || BY_CODE[code] === undefined)) return 'S13';
  return (code !== null ? BY_CODE[code] : undefined) ?? 'S26';
}

/** What `stopForSdkError` answers when the reason is not a stop at all. */
export type SdkErrorOutcome = StopId | 'cancelled' | 'popup-blocked';

/** Which page an error the SDK raised belongs on. */
export function stopForSdkError(error: { readonly code: string }): SdkErrorOutcome {
  switch (error.code) {
    case 'UNAUTHORIZED': return 'S22';
    case 'USER_CANCELLED': return 'cancelled';
    case 'POPUP_BLOCKED': return 'popup-blocked';
    case 'APP_KEY_GRANT_REFUSED': return 'S20';
    case 'KEY_DELETE_NOT_GRANTABLE': return 'S21';
    case 'INVALID_SIWE_RECAP': return 'S11';
    default: return 'S26';
  }
}

/**
 * The support line: the HTTP status and the code, nothing else. A code that is not a safe code is left out, and
 * with neither the line is empty.
 */
export function supportLine(input: { status?: number; code?: unknown }): string {
  const code = safeCode(input.code);
  const parts: string[] = [];
  if (input.status !== undefined) parts.push(`HTTP ${input.status}`);
  if (code !== null) parts.push(code);
  return parts.join(' · ');
}
