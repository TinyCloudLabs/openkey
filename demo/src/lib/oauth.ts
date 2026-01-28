// OAuth 2.1 utilities for OpenKey authentication

// Configuration
export const OPENKEY_HOST = import.meta.env.VITE_OPENKEY_HOST || 'https://openkey.so';
export const CLIENT_ID = import.meta.env.VITE_CLIENT_ID || 'demo_client';
export const REDIRECT_URI = typeof window !== 'undefined'
  ? `${window.location.origin}/callback`
  : 'http://localhost:5174/callback';

// PKCE utilities

/**
 * Generate a cryptographically random code verifier for PKCE
 */
export async function generateCodeVerifier(): Promise<string> {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

/**
 * Generate a code challenge from a code verifier using SHA-256
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Generate a random state parameter for CSRF protection
 */
export function generateState(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

/**
 * Base64 URL encode a byte array
 */
function base64UrlEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Build the authorization URL for the OAuth flow
 */
export function getAuthorizationUrl(state: string, codeChallenge: string): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid',
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  return `${OPENKEY_HOST}/api/auth/oauth2/authorize?${params.toString()}`;
}

/**
 * Exchange an authorization code for tokens
 */
export async function exchangeCode(code: string, codeVerifier: string): Promise<{
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in: number;
}> {
  const response = await fetch(`${OPENKEY_HOST}/api/auth/oauth2/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: codeVerifier,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Token exchange failed: ${error}`);
  }

  return response.json();
}

/**
 * Parse and decode an ID token (JWT)
 * Note: This does not verify the signature - for demo purposes only
 */
export function parseIdToken(idToken: string): { sub: string; iat: number; exp: number } {
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid ID token format');
  }

  const payload = parts[1];
  // Add padding if needed
  const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
  const decoded = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));

  return JSON.parse(decoded);
}

// Storage keys
const PKCE_KEY = 'openkey_pkce';
const TOKENS_KEY = 'openkey_tokens';

/**
 * Store PKCE values in sessionStorage
 */
export function storePKCE(verifier: string, state: string): void {
  if (typeof sessionStorage !== 'undefined') {
    sessionStorage.setItem(PKCE_KEY, JSON.stringify({ verifier, state }));
  }
}

/**
 * Retrieve PKCE values from sessionStorage
 */
export function getPKCE(): { verifier: string; state: string } | null {
  if (typeof sessionStorage === 'undefined') {
    return null;
  }
  const data = sessionStorage.getItem(PKCE_KEY);
  if (!data) {
    return null;
  }
  return JSON.parse(data);
}

/**
 * Clear PKCE values from sessionStorage
 */
export function clearPKCE(): void {
  if (typeof sessionStorage !== 'undefined') {
    sessionStorage.removeItem(PKCE_KEY);
  }
}

/**
 * Store tokens in sessionStorage
 */
export function storeTokens(tokens: {
  accessToken: string;
  idToken: string;
  expiresAt: number;
}): void {
  if (typeof sessionStorage !== 'undefined') {
    sessionStorage.setItem(TOKENS_KEY, JSON.stringify(tokens));
  }
}

/**
 * Retrieve tokens from sessionStorage
 */
export function getTokens(): {
  accessToken: string;
  idToken: string;
  expiresAt: number;
} | null {
  if (typeof sessionStorage === 'undefined') {
    return null;
  }
  const data = sessionStorage.getItem(TOKENS_KEY);
  if (!data) {
    return null;
  }
  return JSON.parse(data);
}

/**
 * Clear tokens from sessionStorage
 */
export function clearTokens(): void {
  if (typeof sessionStorage !== 'undefined') {
    sessionStorage.removeItem(TOKENS_KEY);
  }
}
