import { createAuthClient } from 'better-auth/svelte';
import { emailOTPClient } from 'better-auth/client/plugins';

export const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3001';

export const authClient = createAuthClient({
  baseURL: API_BASE,
  fetchOptions: {
    credentials: 'include',
  },
  plugins: [emailOTPClient()],
});

export const { signIn, signOut, useSession } = authClient;
