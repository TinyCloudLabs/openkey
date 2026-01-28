import { writable } from 'svelte/store';
import { getTokens, clearTokens, parseIdToken } from './oauth';

export interface AuthState {
  isAuthenticated: boolean;
  accessToken: string | null;
  idToken: string | null;
  user: { sub: string } | null;
}

const initialState: AuthState = {
  isAuthenticated: false,
  accessToken: null,
  idToken: null,
  user: null,
};

export const auth = writable<AuthState>(initialState);

/**
 * Logout - clear tokens and reset auth state
 */
export function logout(): void {
  clearTokens();
  auth.set(initialState);
}

/**
 * Load authentication state from sessionStorage
 */
export function loadAuthFromStorage(): void {
  const tokens = getTokens();

  if (!tokens) {
    auth.set(initialState);
    return;
  }

  // Check if tokens are expired
  if (Date.now() >= tokens.expiresAt) {
    clearTokens();
    auth.set(initialState);
    return;
  }

  // Parse the ID token to get user info
  try {
    const payload = parseIdToken(tokens.idToken);
    auth.set({
      isAuthenticated: true,
      accessToken: tokens.accessToken,
      idToken: tokens.idToken,
      user: { sub: payload.sub },
    });
  } catch {
    // Invalid token, clear everything
    clearTokens();
    auth.set(initialState);
  }
}

/**
 * Set authentication state after successful login
 */
export function setAuthenticated(accessToken: string, idToken: string): void {
  try {
    const payload = parseIdToken(idToken);
    auth.set({
      isAuthenticated: true,
      accessToken,
      idToken,
      user: { sub: payload.sub },
    });
  } catch {
    auth.set(initialState);
  }
}
