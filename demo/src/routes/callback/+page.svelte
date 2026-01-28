<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import {
    getPKCE,
    clearPKCE,
    exchangeCode,
    storeTokens,
    parseIdToken,
  } from '$lib/oauth';
  import { setAuthenticated } from '$lib/stores';

  let error = $state('');
  let status = $state('Processing authentication...');

  onMount(async () => {
    try {
      // Parse URL parameters
      const params = new URLSearchParams(window.location.search);
      const code = params.get('code');
      const state = params.get('state');
      const errorParam = params.get('error');
      const errorDescription = params.get('error_description');

      // Check for OAuth error response
      if (errorParam) {
        throw new Error(errorDescription || errorParam);
      }

      // Validate required parameters
      if (!code) {
        throw new Error('Missing authorization code');
      }

      if (!state) {
        throw new Error('Missing state parameter');
      }

      // Retrieve and validate PKCE values
      const pkce = getPKCE();
      if (!pkce) {
        throw new Error('No PKCE data found. Please try logging in again.');
      }

      // Verify state matches to prevent CSRF
      if (pkce.state !== state) {
        throw new Error('State mismatch. This may be a CSRF attack.');
      }

      status = 'Exchanging authorization code...';

      // Exchange code for tokens
      const tokens = await exchangeCode(code, pkce.verifier);

      // Clear PKCE data
      clearPKCE();

      // Parse ID token to get expiration
      const payload = parseIdToken(tokens.id_token);
      const expiresAt = payload.exp * 1000; // Convert to milliseconds

      // Store tokens
      storeTokens({
        accessToken: tokens.access_token,
        idToken: tokens.id_token,
        expiresAt,
      });

      // Update auth state
      setAuthenticated(tokens.access_token, tokens.id_token);

      status = 'Authentication successful! Redirecting...';

      // Redirect to home page
      await goto('/', { replaceState: true });
    } catch (err) {
      clearPKCE();
      error = err instanceof Error ? err.message : 'Authentication failed';
    }
  });
</script>

<div class="flex min-h-[60vh] flex-col items-center justify-center">
  {#if error}
    <div class="w-full max-w-md rounded-xl border border-red-800 bg-red-900/20 p-6">
      <h2 class="mb-2 text-lg font-semibold text-red-400">Authentication Failed</h2>
      <p class="mb-4 text-surface-300">{error}</p>
      <a
        href="/login"
        class="inline-flex items-center justify-center rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-primary-700"
      >
        Try Again
      </a>
    </div>
  {:else}
    <div class="text-center">
      <div class="mb-4 h-8 w-8 animate-spin rounded-full border-2 border-primary-600 border-t-transparent mx-auto"></div>
      <p class="text-surface-400">{status}</p>
    </div>
  {/if}
</div>
