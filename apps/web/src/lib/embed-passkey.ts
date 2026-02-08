// Tokenized passkey flow for iframe embed context.
// Bypasses cookie-based better-auth by calling proxy endpoints
// that return a challengeToken + sessionToken in the JSON body.

import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3001';

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

export function clearSessionToken(): void {
  sessionStorage.removeItem(SESSION_TOKEN_KEY);
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
