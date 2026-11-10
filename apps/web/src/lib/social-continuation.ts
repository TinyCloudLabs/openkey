// TC-1232: what the web shows after Google or Apple returns. The API answers
// a sign-in that needs a choice with `error=new_account|account_exists` and a
// one-time `continuation` bound to a cookie (and, in native mode, to the
// signed authorize query); every other `error` is a failure with its own copy.
import { API_BASE } from './auth-client';
import type { SocialProviderId } from './social-auth';

export type SocialOutcome = 'new_account' | 'account_exists';

export interface SocialContinuation {
  token: string;
  outcome: SocialOutcome;
  provider: SocialProviderId;
  email: string;
  /** Apple Hide My Email: the address is a relay, never an existing account's email (R4). */
  isPrivateEmail: boolean;
}

/** Marks which provider the popup came back from; the provider's own redirect carries no such hint. */
export const SOCIAL_RETURN_PARAM = 'via';
/** On the popup's return URL: it was started from /auth/register, an explicit sign-up. */
export const SOCIAL_SIGNUP_INTENT_PARAM = 'signup';

const APPLE_RELAY_DOMAIN = '@privaterelay.appleid.com';

export function socialProviderName(provider: SocialProviderId): 'Google' | 'Apple' {
  return provider === 'apple' ? 'Apple' : 'Google';
}

export function socialProviderParam(value: string | null | undefined): SocialProviderId | null {
  return value === 'google' || value === 'apple' ? value : null;
}

export function isAppleRelayEmail(email: string): boolean {
  return email.trim().toLowerCase().endsWith(APPLE_RELAY_DOMAIN);
}

export const APPLE_RELAY_NOTICE =
  'Apple is hiding your email, so this creates a new OpenKey account. Already have one? Sign in to it and add Apple in Settings.';

export const APPLE_EMAIL_REQUIRED_MESSAGE =
  "Apple didn't share a verified email, so OpenKey can't create an account from it. Sign in with your email or passkey, then add Apple in Settings.";

/** R4: the notice the new-account confirmation shows, or null. */
export function relayNotice(continuation: Pick<SocialContinuation, 'provider' | 'email' | 'isPrivateEmail'>): string | null {
  if (continuation.provider !== 'apple') return null;
  return continuation.isPrivateEmail || isAppleRelayEmail(continuation.email) ? APPLE_RELAY_NOTICE : null;
}

/** R3: an existing account is never linked here; the user signs in and links from Settings after an email code. */
export function accountExistsMessage(provider: SocialProviderId, email: string): string {
  return `An OpenKey account already uses ${email}. Sign in to it and verify with an email code to add ${socialProviderName(provider)}.`;
}

/** Copy for a provider return that failed. `provider` is null when the return did not say. */
export function socialErrorMessage(provider: SocialProviderId | null, code: string | null): string {
  const name = provider ? socialProviderName(provider) : 'The provider';
  switch (code) {
    case 'apple_email_required':
      return APPLE_EMAIL_REQUIRED_MESSAGE;
    case 'account_not_linked':
      return `An OpenKey account already uses this email. Sign in to it and add ${provider ? socialProviderName(provider) : 'this sign-in method'} in Settings.`;
    case 'access_denied':
    case 'user_cancelled_authorize':
      return `${provider ? socialProviderName(provider) : 'Social'} sign-in was cancelled.`;
    case 'account_already_linked_to_different_user':
      return `This ${provider ? socialProviderName(provider) : 'sign-in'} account is already linked to another OpenKey account.`;
    case 'unable_to_link_account':
      return `OpenKey could not link ${provider ? socialProviderName(provider) : 'this account'}. Verify a new email code in Settings and try again.`;
    case 'continuation_expired':
      return `This ${provider ? socialProviderName(provider) : 'sign-in'} confirmation expired. Start sign-in again.`;
    default:
      return `${name} could not complete sign-in. Please try again.`;
  }
}

export type SocialPopupAction = 'link' | 'signup';

export type SocialCallback =
  | { kind: 'start'; provider: SocialProviderId; action: SocialPopupAction | null }
  | { kind: 'continuation'; provider: SocialProviderId | null; outcome: SocialOutcome; token: string; signupIntent: boolean }
  | { kind: 'error'; provider: SocialProviderId | null; code: string }
  | { kind: 'complete'; provider: SocialProviderId | null };

/** Reads the popup callback URL: start a provider, ask about a continuation, show an error, or hand off the session. */
export function parseSocialCallback(url: URL): SocialCallback {
  const params = url.searchParams;
  const start = socialProviderParam(params.get('provider'));
  if (start) {
    const action = params.get('action');
    return { kind: 'start', provider: start, action: action === 'link' || action === 'signup' ? action : null };
  }
  const code = params.get('error');
  // `apple_email_required` is only ever produced for Apple.
  const provider = socialProviderParam(params.get(SOCIAL_RETURN_PARAM))
    ?? (code === 'apple_email_required' ? 'apple' : null);
  const token = params.get('continuation');
  if ((code === 'new_account' || code === 'account_exists') && token) {
    return { kind: 'continuation', provider, outcome: code, token, signupIntent: params.get(SOCIAL_SIGNUP_INTENT_PARAM) === '1' };
  }
  if (code !== null) {
    return { kind: 'error', provider, code: code === 'new_account' || code === 'account_exists' ? 'continuation_expired' : code };
  }
  return { kind: 'complete', provider };
}

/** The popup's provider return URL: names the provider, and carries /auth/register's sign-up intent. */
export function socialPopupReturnUrl(origin: string, provider: SocialProviderId, action: SocialPopupAction | null): string {
  const url = new URL('/auth/social/callback', origin);
  url.searchParams.set(SOCIAL_RETURN_PARAM, provider);
  if (action === 'signup') url.searchParams.set(SOCIAL_SIGNUP_INTENT_PARAM, '1');
  return url.href;
}

/**
 * Reads the continuation's display data. The API checks the binding cookie
 * (and `oauthQuery` against the native request), so an answer that does not
 * match the outcome the redirect named is refused, not shown.
 */
export async function loadSocialContinuation(
  input: { token: string; outcome: SocialOutcome; provider: SocialProviderId | null; oauthQuery?: string },
  fetchImpl: typeof fetch = fetch,
): Promise<SocialContinuation> {
  const params = new URLSearchParams({ continuation: input.token });
  if (input.oauthQuery) params.set('oauthQuery', input.oauthQuery);
  const expired = new Error(socialErrorMessage(input.provider, 'continuation_expired'));
  let response: Response;
  try {
    response = await fetchImpl(`${API_BASE}/api/auth/social/continuation?${params}`, {
      credentials: 'include', headers: { Accept: 'application/json' },
    });
  } catch {
    throw new Error(socialErrorMessage(input.provider, null));
  }
  if (!response.ok) throw expired;
  const body = await response.json().catch(() => null) as Record<string, unknown> | null;
  const provider = socialProviderParam(typeof body?.providerId === 'string' ? body.providerId : null);
  if (!body || !provider || body.outcome !== input.outcome || typeof body.email !== 'string' || !body.email
    || (input.provider && provider !== input.provider)) {
    throw new Error(socialErrorMessage(input.provider ?? provider, 'continuation_expired'));
  }
  return {
    token: input.token,
    outcome: input.outcome,
    provider,
    email: body.email,
    isPrivateEmail: body.isPrivateEmail === true,
  };
}

/** Create: spends the continuation and returns the new session's token. */
export async function confirmSocialContinuation(
  input: { token: string; provider: SocialProviderId; oauthQuery?: string },
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  let response: Response;
  try {
    response = await fetchImpl(`${API_BASE}/api/auth/social/confirm`, {
      method: 'POST', credentials: 'include',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ continuation: input.token, ...(input.oauthQuery ? { oauthQuery: input.oauthQuery } : {}) }),
    });
  } catch {
    throw new Error('Could not reach OpenKey. Check your connection and try again.');
  }
  const body = await response.json().catch(() => null) as Record<string, unknown> | null;
  if (response.ok && typeof body?.token === 'string' && body.token) return body.token;
  const name = socialProviderName(input.provider);
  if (body?.code === 'ACCOUNT_ALREADY_EXISTS') {
    throw new Error(`An OpenKey account already uses this email. Sign in to it and add ${name} in Settings.`);
  }
  if (body?.code === 'ACCOUNT_ALREADY_LINKED') {
    throw new Error(`This ${name} account is already linked to an OpenKey account. Sign in with ${name} instead.`);
  }
  throw new Error(`Could not create your account. Start ${name} sign-in again.`);
}
