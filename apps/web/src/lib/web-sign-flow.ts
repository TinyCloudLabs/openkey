// One passkey per web sign interaction. The sign pop-up and iframe each draw a fresh flow id in OpenKey's own page
// code and name it on the passkey sign-in, the offer and the approval of that one request. The API records a cover
// for it only after a user-verified passkey sign-in, so Approve for that request asks for no second passkey. The id
// is never read from the app's request data or its postMessage: the app is not trusted with it.
import { getSessionToken, isEmbedContext } from './embed-passkey';

/** Header that names the web sign flow on a request. */
export const WEB_SIGN_FLOW_HEADER = 'x-openkey-passkey-flow';

/** The shape the API accepts for a web flow: `w.` and 24 random bytes in base64url. */
const WEB_SIGN_FLOW_ID = /^w\.[A-Za-z0-9_-]{32}$/;
/** Where the pop-up tab keeps its flow id while the user signs in on the login page. */
const POPUP_FLOW_KEY = 'openkey_sign_flow';

const API_BASE = import.meta.env.VITE_API_URL || '';

export function newWebSignFlowId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return `w.${btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
}

export function isWebSignFlowId(value: unknown): value is string {
  return typeof value === 'string' && WEB_SIGN_FLOW_ID.test(value);
}

export function webSignFlowHeaders(flowId: string): Record<string, string> {
  return { [WEB_SIGN_FLOW_HEADER]: flowId };
}

type FlowStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

// The tab's own storage: a pop-up tab does not share it with the app that opened it or with any other tab.
function tabStorage(): FlowStorage | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage;
  } catch {
    return null;
  }
}

/** Keeps the page's flow id in this tab across the trip to the login page. */
export function carryPopupSignFlow(flowId: string, storage: FlowStorage | null = tabStorage()): void {
  try {
    storage?.setItem(POPUP_FLOW_KEY, flowId);
  } catch {
    // Without storage the sign-in carries no flow and Approve asks for its own passkey.
  }
}

/** The carried flow id when it has the web shape; anything else in storage is ignored. */
export function peekPopupSignFlow(storage: FlowStorage | null = tabStorage()): string | null {
  try {
    const value = storage?.getItem(POPUP_FLOW_KEY);
    return isWebSignFlowId(value) ? value : null;
  } catch {
    return null;
  }
}

/** Reads the carried flow id and forgets it, so one tab visit to the login page serves one sign page. */
export function takePopupSignFlow(storage: FlowStorage | null = tabStorage()): string | null {
  const flowId = peekPopupSignFlow(storage);
  try {
    storage?.removeItem(POPUP_FLOW_KEY);
  } catch {
    // Nothing more to forget.
  }
  return flowId;
}

// One document serves one sign request. The login round trip is a client-side navigation, so the sign page can be
// created more than once in the same document; each instance reads the same id, drawn or carried once.
let documentFlowId: string | null = null;

/**
 * The pop-up page's flow id for this document: the id carried across the login page when there is one, otherwise a new
 * one, and the same id for every page instance created in this document. A new document draws or reads its own.
 */
export function popupSignFlowId(storage: FlowStorage | null = tabStorage()): string {
  const carried = takePopupSignFlow(storage);
  if (carried) documentFlowId = carried;
  documentFlowId ??= newWebSignFlowId();
  return documentFlowId;
}

/** Ends this document's flow id when its request ends, so a later request in the same document draws its own. */
export function forgetPopupSignFlow(): void {
  documentFlowId = null;
}

/**
 * The flow id the login page names on its passkey sign-in: only when the page returns the user to the sign pop-up, and
 * only a carried id with the web shape. A login for anything else names no flow.
 */
export function popupSignFlowForLogin(redirect: string | null, pageOrigin: string, storage: FlowStorage | null = tabStorage()): string | null {
  if (!redirect) return null;
  try {
    const target = new URL(redirect, pageOrigin);
    if (target.origin !== pageOrigin || target.pathname !== '/widget/sign') return null;
  } catch {
    return null;
  }
  return peekPopupSignFlow(storage);
}

/**
 * Ends the passkey cover this page's sign-in recorded when the request is cancelled or refused. Best effort: the cover
 * also ends on its own after five minutes. The page's own credential goes with it, as for its other calls.
 */
export async function releaseWebSignFlow(flowId: string, fetchImpl: typeof fetch = fetch): Promise<void> {
  try {
    const token = isEmbedContext() ? getSessionToken() : null;
    await fetchImpl(`${API_BASE}/api/delegate/authorize-sign-release`, {
      method: 'POST',
      keepalive: true,
      credentials: token ? 'omit' : 'include',
      headers: { 'Content-Type': 'application/json', ...webSignFlowHeaders(flowId), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: '{}',
    });
  } catch {
    // The cover expires by itself.
  }
}
