// The account setup page's message protocol (/widget/account-setup and the embedded hand-off at
// /widget/embed/account-setup).
//
// Popup: the app's window opens the page (or the connect window it opened navigates itself here) and sends one
// `openkey:account-setup:request` after `openkey:ready`. The page takes it only from its opener and only from the
// exact `?origin=`, and answers once with the same `requestId` and `protocolVersion`.
// Embed: the app frames the hand-off, which takes the request from its parent the same way and opens the popup from the
// owner's tap. The popup then talks to the hand-off (an OpenKey origin) and the hand-off relays the answer.
//
// The answer never carries the account's address, subject or node: the app reads the registry itself.

export const ACCOUNT_SETUP_REQUEST = 'openkey:account-setup:request';
export const ACCOUNT_SETUP_RESPONSE = 'openkey:account-setup:response';
export const ACCOUNT_SETUP_PROTOCOL_VERSION = 1;

/** Where an owner finishes a setup OpenKey cannot do here: a wallet key, or a location of their own. First-party. */
export const TINYCLOUD_ONE_SETUP_URL = 'https://tinycloud.one/?finish-setup=registry';

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

function exactOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || value === 'null' || value === '*') return null;
  try {
    return new URL(value).origin === value ? value : null;
  } catch {
    return null;
  }
}

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
  const requester = relayed ? exactOrigin(data.requestOrigin) : event.origin;
  if (requester === null) return null;
  return {
    requestId: data.requestId,
    protocolVersion: ACCOUNT_SETUP_PROTOCOL_VERSION,
    keyId: typeof data.keyId === 'string' ? data.keyId : null,
    requester,
  };
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
