// Tokenized passkey flow for iframe embed context.
// Bypasses cookie-based better-auth by calling proxy endpoints
// that return a challengeToken + sessionToken in the JSON body.

import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

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

export async function embedVerifyEmailOtp(
  email: string,
  otp: string,
  fetchImpl: typeof fetch = fetch,
  persistToken: (token: string) => void = setSessionToken,
): Promise<string> {
  const response = await fetchImpl(`${API_BASE}/api/auth/sign-in/email-otp`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ email, otp }),
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(body?.message || body?.error || 'Invalid code');
  }
  const sessionToken =
    response.headers.get('set-auth-token')
    || body?.token
    || body?.session?.token;
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
        const currentSession = await fetchImpl(
          `${API_BASE}/api/auth/get-session?disableRefresh=true`,
          { credentials: 'include' },
        );
        if (currentSession.ok) {
          const current = await currentSession.json().catch(() => undefined);
          tokenToVerify = current?.session?.token ?? null;
        }
      } catch {
        // Still attempt sign-out so local cookie cleanup is not blocked by a
        // failed preflight. Without the old token, revocation stays unverified.
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
    const verification = await fetchImpl(
      `${API_BASE}/api/auth/get-session?disableRefresh=true`,
      {
        credentials: 'omit',
        headers: { Authorization: `Bearer ${tokenToVerify}` },
      },
    );
    if (!verification.ok) return false;
    return (await verification.json().catch(() => undefined)) === null;
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
