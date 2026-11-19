// Tokenized passkey flow for iframe embed context.
// Bypasses cookie-based better-auth by calling proxy endpoints
// that return a challengeToken + sessionToken in the JSON body.

import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { newAccountSignupToken, SIGN_UP_EMAIL_OTP_PATH } from './email-signup';

const API_BASE = import.meta.env.VITE_API_URL || '';

const SESSION_TOKEN_KEY = 'openkey_session_token';

export function isEmbedContext(): boolean {
  try {
    return window.self !== window.top;
  } catch {
    return true; // cross-origin iframe throws on access
  }
}

export function getSessionToken(): string | null {
  return sessionStorage.getItem(SESSION_TOKEN_KEY);
}

/**
 * Request options with the credential the embedded widget holds. An iframe on
 * another site does not send OpenKey's session cookie, so `lib/api.ts` sends the
 * session token as a bearer credential. This does the same for the widget's own
 * calls: with a token, `Authorization: Bearer <token>` and no cookies; without
 * one, cookies as before.
 */
export function withSessionCredential(init: RequestInit): RequestInit {
  const token = getSessionToken();
  if (!token) return { ...init, credentials: 'include' };
  return {
    ...init,
    credentials: 'omit',
    headers: { ...(init.headers as Record<string, string> | undefined), Authorization: `Bearer ${token}` },
  };
}

export function setSessionToken(token: string): void {
  sessionStorage.setItem(SESSION_TOKEN_KEY, token);
}

export async function embedSendEmailOtp(
  email: string,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const response = await fetchImpl(`${API_BASE}/api/auth/email-otp/send-verification-otp`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ email, type: 'sign-in' }),
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(body?.message || body?.error || 'Failed to send code');
  }
}

/** Signed in, or verified for an email with no account yet (TC-1114). */
export type EmbedEmailOtpResult = { sessionToken: string } | { signupToken: string };

export async function embedVerifyEmailOtp(
  email: string,
  otp: string,
  fetchImpl: typeof fetch = fetch,
  persistToken: (token: string) => void = setSessionToken,
): Promise<EmbedEmailOtpResult> {
  const response = await fetchImpl(`${API_BASE}/api/auth/sign-in/email-otp`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ email, otp }),
  });
  const body = await response.json().catch(() => null);
  const signupToken = newAccountSignupToken(body);
  if (signupToken) return { signupToken };
  return { sessionToken: persistEmbeddedSession(response, body, 'Invalid code', persistToken) };
}

/** Creates the account the user confirmed, with the token from the verified code. */
export async function embedCreateAccount(
  email: string,
  signupToken: string,
  fetchImpl: typeof fetch = fetch,
  persistToken: (token: string) => void = setSessionToken,
): Promise<string> {
  const response = await fetchImpl(`${API_BASE}/api/auth${SIGN_UP_EMAIL_OTP_PATH}`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ email, signupToken }),
  });
  const body = await response.json().catch(() => null);
  return persistEmbeddedSession(response, body, 'Could not create your account', persistToken);
}

function persistEmbeddedSession(
  response: Response,
  body: { message?: string; error?: string; token?: string; session?: { token?: string } } | null,
  failure: string,
  persistToken: (token: string) => void,
): string {
  if (!response.ok) {
    throw new Error(body?.message || body?.error || failure);
  }
  const sessionToken = response.headers.get('set-auth-token');
  if (!sessionToken) {
    throw new Error('Email verified, but no embedded session token was returned.');
  }
  persistToken(sessionToken);
  return sessionToken;
}

export function clearSessionToken(): void {
  sessionStorage.removeItem(SESSION_TOKEN_KEY);
}

/**
 * The current cookie session's token in its signed form, the form the
 * `set-auth-token` header carries, or null when there is no session.
 */
export async function readSignedSessionToken(fetchImpl: typeof fetch = fetch): Promise<string | null> {
  const response = await fetchImpl(`${API_BASE}/api/auth/session-token`, {
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });
  if (response.status !== 404) {
    if (!response.ok) return null;
    const body = await response.json().catch(() => null) as { token?: unknown } | null;
    return typeof body?.token === 'string' && body.token ? body.token : null;
  }
  // An API without /session-token answers 404: read the session as before.
  const session = await fetchImpl(`${API_BASE}/api/auth/get-session`, {
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });
  const body = await session.json().catch(() => null) as { token?: string; session?: { token?: string } } | null;
  return session.headers.get('set-auth-token') || body?.session?.token || body?.token || null;
}

/** Whether `token` authenticates as a bearer, with no cookie and no session refresh. */
async function bearerAuthenticates(token: string, fetchImpl: typeof fetch): Promise<boolean> {
  const response = await fetchImpl(`${API_BASE}/api/auth/get-session?disableRefresh=true`, {
    credentials: 'omit',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error('Session check failed');
  return (await response.json().catch(() => undefined)) !== null;
}

/**
 * Revoke the session used by popup or embedded widgets, then remove the local
 * bearer copy regardless of whether a network or server failure prevented
 * revocation.
 */
export async function revokeEmbeddedSession(
  sessionToken: string | null = getSessionToken(),
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  let tokenToVerify = sessionToken;

  try {
    // Popup-mode clients authenticate with a cookie and do not have a bearer
    // token to relay. Capture that session's token before sign-out so the
    // post-sign-out check can prove that the same server-side session was
    // deleted after the browser cookie has been cleared.
    if (!tokenToVerify) {
      try {
        tokenToVerify = await readSignedSessionToken(fetchImpl);
      } catch {
        // Still attempt sign-out so local cookie cleanup is not blocked by a
        // failed preflight. Without the old token, revocation stays unverified.
      }
    }

    // A token that does not authenticate before sign-out proves nothing by
    // failing to authenticate after it, so it is not used to verify.
    if (tokenToVerify) {
      try {
        if (!await bearerAuthenticates(tokenToVerify, fetchImpl)) tokenToVerify = null;
      } catch {
        tokenToVerify = null;
      }
    }

    const response = await fetchImpl(`${API_BASE}/api/auth/sign-out`, {
      method: 'POST',
      credentials: 'include',
      headers: tokenToVerify ? { Authorization: `Bearer ${tokenToVerify}` } : undefined,
    });
    if (!response.ok) return false;

    // A null cookie-session response is not proof of revocation in a
    // cross-site iframe, where SameSite policy may simply omit the cookie.
    if (!tokenToVerify) return false;

    // Better Auth clears cookies and returns 200 even when deleting the
    // database session fails. Re-check the previous bearer without cookies or
    // session refresh so `revoked: true` means that exact old session can no
    // longer authenticate, not merely that sign-out was accepted.
    return !await bearerAuthenticates(tokenToVerify, fetchImpl);
  } catch {
    return false;
  } finally {
    clearSessionToken();
  }
}

export async function embedSignInPasskey(): Promise<{ session: any; user: any; sessionToken: string }> {
  // 1. Get authentication options + challengeToken
  const optionsRes = await fetch(`${API_BASE}/api/passkey/generate-authenticate-options`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
  if (!optionsRes.ok) {
    const err = await optionsRes.json().catch(() => ({ error: 'Failed to get passkey options' }));
    throw new Error(err.error || `HTTP ${optionsRes.status}`);
  }
  const options = await optionsRes.json();
  const { challengeToken, ...authOptions } = options;

  // 2. Prompt user for passkey via WebAuthn browser API
  const assertion = await startAuthentication(authOptions);

  // 3. Verify with server, get session token back
  const verifyRes = await fetch(`${API_BASE}/api/passkey/verify-authentication`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ response: assertion, challengeToken }),
  });
  if (!verifyRes.ok) {
    const err = await verifyRes.json().catch(() => ({ error: 'Passkey verification failed' }));
    throw new Error(err.error || `HTTP ${verifyRes.status}`);
  }
  const result = await verifyRes.json();

  // 4. Store session token for subsequent API calls
  if (result.sessionToken) {
    sessionStorage.setItem(SESSION_TOKEN_KEY, result.sessionToken);
  }

  return result;
}

export async function embedRegisterPasskey(name?: string): Promise<any> {
  // 1. Get registration options + challengeToken
  const optionsRes = await fetch(`${API_BASE}/api/passkey/generate-register-options`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  if (!optionsRes.ok) {
    const err = await optionsRes.json().catch(() => ({ error: 'Failed to get registration options' }));
    throw new Error(err.error || `HTTP ${optionsRes.status}`);
  }
  const options = await optionsRes.json();
  const { challengeToken, ...registrationOptions } = options;

  // 2. Prompt user for passkey creation via WebAuthn browser API
  const attestation = await startRegistration(registrationOptions);

  // 3. Verify registration with server
  const verifyRes = await fetch(`${API_BASE}/api/passkey/verify-registration`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ response: attestation, name, challengeToken }),
  });
  if (!verifyRes.ok) {
    const err = await verifyRes.json().catch(() => ({ error: 'Registration verification failed' }));
    throw new Error(err.error || `HTTP ${verifyRes.status}`);
  }
  const result = await verifyRes.json();

  if (result.sessionToken) {
    sessionStorage.setItem(SESSION_TOKEN_KEY, result.sessionToken);
  }

  return result;
}
