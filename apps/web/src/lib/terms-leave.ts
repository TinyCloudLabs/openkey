// TC-3232: "Don't agree" on the Terms screen. It first tells whoever sent the account there that the answer
// is no (an OAuth or native app, an approval link, a device sign-in), then declines: the API stops the
// account's renewals and signs it out. Telling the requester no is best effort and never stops the leaving.
import { API_BASE, authClient } from './auth-client';
import { safeOAuthNavigationUrl } from './safe-oauth-url';
import { signedOAuthQuery } from './terms';

export type TermsOrigin =
  | { kind: 'oauth'; oauthQuery: string; nativeRequestId: string | null }
  | { kind: 'approval'; requestId: string }
  | { kind: 'device'; transactionId: string }
  | { kind: 'none' };

const NONE: TermsOrigin = { kind: 'none' };
const APPROVAL_PATH = /^\/a\/([a-z2-7]{26})$/;

function oauth(oauthQuery: string, params: URLSearchParams): TermsOrigin {
  const nativeRequestId = params.get('client_id') ? params.get('tinycloud_request') : null;
  return { kind: 'oauth', oauthQuery, nativeRequestId: nativeRequestId || null };
}

/**
 * The request that brought the account to the Terms: this page's own signed authorize query (sign-in),
 * else the same-origin page it was sent from (`returnTo`).
 */
export function termsOrigin(pageSearch: string, returnTo: string | null): TermsOrigin {
  const own = signedOAuthQuery(pageSearch);
  if (own) return oauth(own, new URLSearchParams(pageSearch));
  if (!returnTo || !returnTo.startsWith('/') || returnTo.startsWith('//')) return NONE;
  let target: URL;
  try {
    target = new URL(returnTo, 'https://openkey.invalid');
  } catch {
    return NONE;
  }
  if (target.pathname === '/oauth/consent') {
    const query = signedOAuthQuery(target.search);
    return query ? oauth(query, target.searchParams) : NONE;
  }
  const approval = APPROVAL_PATH.exec(target.pathname);
  if (approval) return { kind: 'approval', requestId: approval[1]! };
  const transactionId = target.pathname === '/delegate' ? target.searchParams.get('deviceTransactionId') : null;
  return transactionId ? { kind: 'device', transactionId } : NONE;
}

/** What declining does; with a request, that it is turned down too. */
export function declineEffect(origin: TermsOrigin, appName: string | null): string {
  const effect = 'You can’t use OpenKey or sign in to apps with it until you agree. Nothing is deleted. Apps keep the access you’ve already approved until it runs out, but they won’t renew it.';
  if (origin.kind === 'none') return effect;
  return `${effect} ${appName ? `We’ll also tell ${appName} you said no.` : 'We’ll also turn down the request that brought you here.'}`;
}

/**
 * The standalone Terms screen for the same request. Other options and Disconnect apps keep it (as
 * `returnTo`) to come back to, and to find the request again, since sign-in and sign-up show the Terms inline.
 */
export function termsPageFor(pageSearch: string, returnTo: string | null): string {
  const query = signedOAuthQuery(pageSearch);
  if (query) return `/auth/terms?${query}`;
  return returnTo ? `/auth/terms?returnTo=${encodeURIComponent(returnTo)}` : '/auth/terms';
}

/** The Terms screen a ways-out page was given, never anywhere else. */
export function termsPageFrom(returnTo: string | null): string {
  return returnTo && /^\/auth\/terms(?:\?|$)/.test(returnTo) ? returnTo : '/auth/terms';
}

/** The request a Terms screen address carries, read as the Terms page reads it. */
export function originOfTermsPage(termsPage: string): TermsOrigin {
  const url = new URL(termsPage, 'https://openkey.invalid');
  return termsOrigin(url.search, url.searchParams.get('returnTo'));
}

/** Page 2, Other options: sign out without agreeing, or delete the account. */
export function optionsHref(termsPage: string): string {
  return `/auth/terms/options?returnTo=${encodeURIComponent(termsPage)}`;
}

/** Page 3, Disconnect apps: apps, renewals and deletion. */
export function disconnectHref(termsPage: string): string {
  return `/auth/terms/leave?returnTo=${encodeURIComponent(termsPage)}`;
}

export interface DeclineDeps {
  apiBase: string;
  fetch: typeof fetch;
  /** Where an approval link keeps its reference across sign-in (the tab's sessionStorage). */
  storage: Pick<Storage, 'getItem' | 'removeItem'> | null;
  /** The plain sign-out, used when the API's decline can't be reached or refuses. */
  signOut: () => Promise<void>;
}

function post(deps: DeclineDeps, path: string, body?: unknown, init: RequestInit = {}): Promise<Response> {
  return deps.fetch(`${deps.apiBase}${path}`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
    ...init,
  });
}

/** Denies the request; for OAuth, returns the app's answer to go to (its redirect with `access_denied`). */
async function denyOrigin(origin: TermsOrigin, deps: DeclineDeps): Promise<string | null> {
  switch (origin.kind) {
    case 'oauth': {
      if (origin.nativeRequestId) {
        await post(deps, `/api/oauth/tinycloud/requests/${encodeURIComponent(origin.nativeRequestId)}/deny`).catch(() => null);
      }
      const response = await post(deps, '/api/auth/oauth2/consent', { accept: false, oauth_query: origin.oauthQuery });
      if (!response.ok) return null;
      const data = await response.json().catch(() => ({}));
      return safeOAuthNavigationUrl(data.uri ?? data.url ?? (typeof data.redirect === 'string' ? data.redirect : undefined));
    }
    case 'approval': {
      const key = `openkey.approval.${origin.requestId}`;
      const fragment = deps.storage?.getItem(key);
      if (!fragment) return null;
      const response = await post(deps, `/api/approval-requests/${origin.requestId}/deny`, { reference: `/a/${origin.requestId}${fragment}` }, {
        redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
      });
      // Declined now, approved already (409) or expired (410): the link has no further use in this tab.
      if (response.ok || response.status === 409 || response.status === 410) deps.storage?.removeItem(key);
      return null;
    }
    case 'device':
      await post(deps, `/api/device-authorizations/${encodeURIComponent(origin.transactionId)}/deny`);
      return null;
    case 'none':
      return null;
  }
}

/**
 * Says no to the requester, then declines the Terms. Resolves once the account is signed out, with the
 * app's redirect to follow, if any; rejects only when signing out failed.
 */
export async function declineTerms(origin: TermsOrigin, deps: DeclineDeps): Promise<{ redirect: string | null }> {
  const redirect = await denyOrigin(origin, deps).catch(() => null);
  const declined = await post(deps, '/api/account/terms/decline').then((response) => response.ok, () => false);
  if (!declined) await deps.signOut();
  return { redirect };
}

/** `declineTerms` from this tab: its API, its sessionStorage and the plain sign-out. */
export function declineHere(origin: TermsOrigin): Promise<{ redirect: string | null }> {
  let storage: Storage | null = null;
  try {
    storage = window.sessionStorage;
  } catch {
    // Blocked storage: an approval link can't be found again, and is left alone.
  }
  return declineTerms(origin, {
    apiBase: API_BASE,
    fetch,
    storage,
    signOut: async () => {
      const result = await authClient.signOut();
      if (result?.error) throw new Error('sign-out failed');
    },
  });
}
