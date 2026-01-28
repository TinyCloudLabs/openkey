// better-auth client for SvelteKit
import { createAuthClient } from 'better-auth/svelte';
import { passkeyClient } from '@better-auth/passkey/client';
import { emailOTPClient } from 'better-auth/client/plugins';
import { oauthProviderClient } from '@better-auth/oauth-provider/client';

export const authClient = createAuthClient({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:3001',
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
