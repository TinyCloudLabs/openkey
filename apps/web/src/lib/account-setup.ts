// The account setup page's message protocol (/widget/account-setup and the embedded hand-off at
// /widget/embed/account-setup).
//
// Popup: the app's window opens the page and sends one `openkey:account-setup:request` after `openkey:ready`. The page
// takes it only from its opener and only from the exact `?origin=`, and answers once with the same `requestId` and
// `protocolVersion`.
// Hand-off: an OpenKey page (the embedded hand-off, or a sign widget's "Finish setup" card) opens the popup from the
// owner's tap with `?via=embed`. The popup then talks to that OpenKey window, which names the app it verified as
// `requestOrigin`, and the OpenKey window relays the answer.
//
// The answer never carries the account's address, subject or node: the app reads the registry itself.

import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser';
// Relative, not `$lib/`: the mounted widget-page tests stub `$lib/widget-transport` with the transport alone.
import { resolveWidgetOrigin } from './widget-transport';
import { getSessionToken, isEmbedContext } from './embed-passkey';

export const ACCOUNT_SETUP_REQUEST = 'openkey:account-setup:request';
export const ACCOUNT_SETUP_RESPONSE = 'openkey:account-setup:response';
export const ACCOUNT_SETUP_PROTOCOL_VERSION = 1;

/** Where an owner finishes a setup OpenKey cannot do here: a wallet key, or a location of their own. First-party. */
export const TINYCLOUD_ONE_SETUP_URL = 'https://tinycloud.one/?finish-setup=registry';

/** What the owner reads when the account's hourly limit of codes or approval attempts is spent (API code `account_setup_rate_limited`). */
export const ACCOUNT_SETUP_RATE_LIMITED_CODE = 'account_setup_rate_limited';
export const ACCOUNT_SETUP_RATE_LIMITED_MESSAGE = 'Too many attempts in the last hour. Wait an hour, then try once more.';

export type AccountSetupErrorCode = 'USER_CANCELLED' | 'ACCOUNT_SETUP_FAILED' | 'ACCOUNT_SETUP_UNAVAILABLE';

export interface AccountSetupRequest {
  requestId: string;
  protocolVersion: typeof ACCOUNT_SETUP_PROTOCOL_VERSION;
  /** The key the app signed in with, when it named one. */
  keyId: string | null;
  /** The requesting app's origin, read from the message channel: shown to the owner, never trusted. */
  requester: string;
}

export type AccountSetupResponse =
  | {
    type: typeof ACCOUNT_SETUP_RESPONSE;
    requestId: string;
    protocolVersion: typeof ACCOUNT_SETUP_PROTOCOL_VERSION;
    success: true;
    outcome: 'published' | 'present';
  }
  | {
    type: typeof ACCOUNT_SETUP_RESPONSE;
    requestId: string;
    protocolVersion: typeof ACCOUNT_SETUP_PROTOCOL_VERSION;
    success: false;
    error: { code: AccountSetupErrorCode; message: string; setupUrl?: string };
  };

const REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const KEY_ID = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * The request in a message, or null. `counterparty` is the one window the page talks to and `counterpartyOrigin` its
 * exact origin (`?origin=` for the app's window, OpenKey's own origin for the embedded hand-off).
 *
 * The requester is the message's own origin when the app's window sent it. When the hand-off sent it (an OpenKey
 * origin, `relayed`), the requester is the origin the hand-off read from its own parent's message.
 */
export function readAccountSetupRequest(
  event: Pick<MessageEvent, 'origin' | 'source' | 'data'>,
  counterpartyOrigin: string | null,
  counterparty: MessageEventSource | null,
  relayed: boolean,
): AccountSetupRequest | null {
  const data = event.data as Record<string, unknown> | null;
  if (
    counterpartyOrigin === null || counterparty === null ||
    event.origin !== counterpartyOrigin || event.source !== counterparty ||
    !data || typeof data !== 'object' ||
    data.type !== ACCOUNT_SETUP_REQUEST ||
    typeof data.requestId !== 'string' || !REQUEST_ID.test(data.requestId) ||
    data.protocolVersion !== ACCOUNT_SETUP_PROTOCOL_VERSION ||
    (data.keyId !== undefined && data.keyId !== null && (typeof data.keyId !== 'string' || !KEY_ID.test(data.keyId)))
  ) return null;
  const requester = relayed
    ? (typeof data.requestOrigin === 'string' ? resolveWidgetOrigin(data.requestOrigin) : null)
    : event.origin;
  if (requester === null) return null;
  return {
    requestId: data.requestId,
    protocolVersion: ACCOUNT_SETUP_PROTOCOL_VERSION,
    keyId: typeof data.keyId === 'string' ? data.keyId : null,
    requester,
  };
}

const SESSION_TOKEN = /^[\x21-\x7e]{1,4096}$/;

/**
 * The session token an OpenKey hand-off put in its request, or null. Only a valid request from the hand-off window of
 * the OpenKey origin counts (`relayed`); an app's own message never carries one. The reader returns the string and
 * touches no storage: the caller holds it in memory (`setup-bearer.ts`).
 */
export function readAccountSetupBearer(
  event: Pick<MessageEvent, 'origin' | 'source' | 'data'>,
  counterpartyOrigin: string | null,
  counterparty: MessageEventSource | null,
  relayed: boolean,
): string | null {
  const data: unknown = event.data;
  if (readAccountSetupRequest(event, counterpartyOrigin, counterparty, relayed) === null || !relayed) return null;
  if (!data || typeof data !== 'object' || !('sessionToken' in data)) return null;
  const token = data.sessionToken;
  return typeof token === 'string' && SESSION_TOKEN.test(token) ? token : null;
}

export function accountSetupSuccess(request: AccountSetupRequest, outcome: 'published' | 'present'): AccountSetupResponse {
  return {
    type: ACCOUNT_SETUP_RESPONSE,
    requestId: request.requestId,
    protocolVersion: ACCOUNT_SETUP_PROTOCOL_VERSION,
    success: true,
    outcome,
  };
}

export function accountSetupFailure(
  request: AccountSetupRequest, code: AccountSetupErrorCode, message: string,
): AccountSetupResponse {
  return {
    type: ACCOUNT_SETUP_RESPONSE,
    requestId: request.requestId,
    protocolVersion: ACCOUNT_SETUP_PROTOCOL_VERSION,
    success: false,
    error: code === 'ACCOUNT_SETUP_UNAVAILABLE' ? { code, message, setupUrl: TINYCLOUD_ONE_SETUP_URL } : { code, message },
  };
}

/** What `POST /api/account-setup/prepare` answers: a record to approve, or an account that is set up. */
export type AccountSetupPrepared =
  | { state: 'present' }
  | {
    state: 'ready';
    id: string;
    /** The exact record text the approval covers. Shown under "Advanced details". */
    record: string;
    nodeUrl: string;
    expiresAt: string;
    stepUp: 'passkey' | 'email';
  };

/** Where an approved request stands (`/approve` and `/finish`). */
export type AccountSetupState =
  | { state: 'published' | 'present' | 'working' }
  | { state: 'failed'; code: string; error: string; retry: boolean };

/** How the owner confirms this request: the passkey offer, or the masked email a code goes to. */
export type AccountSetupStepUp =
  | { stepUp: 'passkey'; challengeToken: string; options: PublicKeyCredentialRequestOptionsJSON }
  | { stepUp: 'email'; email: string };

export type AccountSetupHandoffResult =
  | { success: true; outcome: 'published' | 'present' }
  | { success: false; error: { code: AccountSetupErrorCode | 'POPUP_BLOCKED'; message: string; setupUrl?: string } };

const POPUP_FEATURES = 'popup=true,width=440,height=720';

/** The token of the session this embedded frame holds, or null (a top-level page uses its cookie). */
function embedSessionToken(): string | null {
  if (!isEmbedContext()) return null;
  try {
    return getSessionToken();
  } catch {
    return null;
  }
}

/**
 * Opens OpenKey's own account setup window for an OpenKey page (the embedded hand-off, a sign widget's card) and relays
 * its answer. Call it straight from the owner's tap: the browser opens a window only from a user gesture.
 *
 * The window is OpenKey's own origin. It is told the app this page verified (`requestOrigin`) and the key, and its
 * answer counts only from that window, from OpenKey's origin and for the request it was sent.
 */
export function openAccountSetupWindow(input: { keyId: string | null; requestOrigin: string }): Promise<AccountSetupHandoffResult> {
  const own = window.location.origin;
  const url = `${own}/widget/account-setup?via=embed&origin=${encodeURIComponent(own)}`;
  const popup = window.open(url, `openkey-account-setup-${Date.now()}`, POPUP_FEATURES);
  if (!popup) {
    return Promise.resolve({ success: false, error: { code: 'POPUP_BLOCKED', message: 'Allow pop-ups for OpenKey to finish setup.' } });
  }
  const requestId = crypto.randomUUID();
  return new Promise((resolve) => {
    let settled = false;
    const settle = (result: AccountSetupHandoffResult) => {
      if (settled) return;
      settled = true;
      window.removeEventListener('message', onMessage);
      clearInterval(closedPoll);
      resolve(result);
    };
    function onMessage(event: MessageEvent) {
      if (event.source !== popup || event.origin !== own) return;
      const data = event.data as Record<string, unknown> | null;
      if (!data || typeof data !== 'object') return;
      // The window asks on each load (a sign-in in between reloads it): the same request each time.
      if (data.type === 'openkey:ready') {
        const sessionToken = embedSessionToken();
        popup!.postMessage({
          type: ACCOUNT_SETUP_REQUEST,
          requestId,
          protocolVersion: ACCOUNT_SETUP_PROTOCOL_VERSION,
          keyId: input.keyId,
          requestOrigin: input.requestOrigin,
          // The embed's own session, for the setup window to call the setup routes with (never in the URL).
          ...(sessionToken ? { sessionToken } : {}),
        }, own);
        return;
      }
      if (data.type !== ACCOUNT_SETUP_RESPONSE || data.requestId !== requestId || data.protocolVersion !== ACCOUNT_SETUP_PROTOCOL_VERSION) return;
      settle(readHandoffAnswer(data));
    }
    const closedPoll = setInterval(() => {
      if (popup.closed) settle({ success: false, error: { code: 'USER_CANCELLED', message: 'The owner closed account setup.' } });
    }, 500);
    window.addEventListener('message', onMessage);
  });
}

const ERROR_CODES: ReadonlySet<string> = new Set(['USER_CANCELLED', 'ACCOUNT_SETUP_FAILED', 'ACCOUNT_SETUP_UNAVAILABLE']);

function readHandoffAnswer(data: Record<string, unknown>): AccountSetupHandoffResult {
  if (data.success === true && (data.outcome === 'published' || data.outcome === 'present')) {
    return { success: true, outcome: data.outcome };
  }
  const error = data.error as { code?: unknown; message?: unknown } | null;
  const code = typeof error?.code === 'string' && ERROR_CODES.has(error.code) ? error.code as AccountSetupErrorCode : 'ACCOUNT_SETUP_FAILED';
  const message = typeof error?.message === 'string' ? error.message.slice(0, 300) : "Setup didn't finish.";
  return {
    success: false,
    error: code === 'ACCOUNT_SETUP_UNAVAILABLE' ? { code, message, setupUrl: TINYCLOUD_ONE_SETUP_URL } : { code, message },
  };
}

/** The hand-off's answer, as the app gets it for its own request. */
export function accountSetupAnswer(request: AccountSetupRequest, result: AccountSetupHandoffResult): AccountSetupResponse {
  if (result.success) return accountSetupSuccess(request, result.outcome);
  // A blocked window is the hand-off's own trouble; the app sees that setup did not finish.
  const code = result.error.code === 'POPUP_BLOCKED' ? 'ACCOUNT_SETUP_FAILED' : result.error.code;
  return accountSetupFailure(request, code, result.error.message);
}

/** The code of the API's refusal to sign a host message for a site that is not TinyCloud's own. */
export const HOST_SIGNING_REFUSAL_CODE = 'host_signing_first_party_only';

/**
 * What the sign widget reports to the app when the owner set the account up from its card and the API refuses the
 * request a second time: the account is set up, and the app repeats its request without hosting the account's
 * spaces. Sent as the message of an `UNKNOWN` error, as the widget's other refusal identifiers are.
 */
export const ACCOUNT_SETUP_COMPLETED = 'ACCOUNT_SETUP_COMPLETED';

/**
 * A host-signing refusal from prepare: `setup` when the API says the account is not set up and the widget knows the
 * app's exact origin (`widgetOrigin`, its `?origin=`) to name on the setup page; `refused` otherwise; null for any
 * other error.
 */
export function hostSigningRefusal(error: unknown, widgetOrigin: string | null): 'setup' | 'refused' | null {
  if (!(error instanceof Error) || !('code' in error) || error.code !== HOST_SIGNING_REFUSAL_CODE) return null;
  const required = 'accountSetup' in error && error.accountSetup === 'required';
  return required && resolveWidgetOrigin(widgetOrigin) !== null ? 'setup' : 'refused';
}
