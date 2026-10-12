// better-auth client for SvelteKit
import { createAuthClient } from 'better-auth/svelte';
import { passkeyClient } from '@better-auth/passkey/client';
import { emailOTPClient } from 'better-auth/client/plugins';
import { oauthProviderClient } from '@better-auth/oauth-provider/client';

export const API_BASE = import.meta.env.VITE_API_URL || '';

export const authClient = createAuthClient({
  baseURL: API_BASE,
  fetchOptions: {
    credentials: 'include',
  },
  plugins: [
    passkeyClient(),
    emailOTPClient(),
    oauthProviderClient(),
  ],
});

// Native-mode Google/Apple redirect. It has no oauthProviderClient, whose
// request hook would add the signed authorize query (and so the native
// request) as `oauth_query` to the social sign-in body.
export const socialRedirectClient = createAuthClient({
  baseURL: API_BASE,
  fetchOptions: {
    credentials: 'include',
  },
});

// Export convenience functions
export const {
  signIn,
  signOut,
  signUp,
  useSession,
} = authClient;

export function authErrorMessage(error: { message?: unknown } | null | undefined, fallback: string): string {
  return typeof error?.message === 'string' ? error.message : fallback;
}
