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
