// better-auth client for SvelteKit
import { createAuthClient } from 'better-auth/svelte';
import { passkeyClient } from '@better-auth/passkey/client';
import { emailOTPClient } from 'better-auth/client/plugins';

export const authClient = createAuthClient({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:3001',
  plugins: [
    passkeyClient(),
    emailOTPClient(),
  ],
});

// Export convenience functions
export const {
  signIn,
  signOut,
  signUp,
  useSession,
} = authClient;
