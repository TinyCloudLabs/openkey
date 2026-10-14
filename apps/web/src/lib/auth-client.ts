// better-auth client for SvelteKit
import { createAuthClient } from 'better-auth/svelte';
import { passkeyClient } from '@better-auth/passkey/client';
import { emailOTPClient } from 'better-auth/client/plugins';
import { oauthProviderClient } from '@better-auth/oauth-provider/client';
import { SIGN_UP_EMAIL_OTP_PATH } from './email-signup';

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

/**
 * Creates the account the user confirmed after a verified email code
 * (TC-1114). A raw `$fetch` does not trigger Better Auth's session signal the
 * way `signIn.emailOtp` does, so this refreshes `useSession` itself.
 */
export async function confirmEmailSignUp(
  body: { email: string; signupToken: string; oauth_query?: string },
  onSuccess?: (context: { data: unknown }) => void,
) {
  const result = await authClient.$fetch(SIGN_UP_EMAIL_OTP_PATH, { method: 'POST', body, onSuccess });
  if (!result.error) authClient.$store.notify('$sessionSignal');
  return result;
}
