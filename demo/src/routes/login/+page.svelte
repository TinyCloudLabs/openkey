<script lang="ts">
  import { onMount } from 'svelte';
  import {
    generateCodeVerifier,
    generateCodeChallenge,
    generateState,
    storePKCE,
    getAuthorizationUrl,
  } from '$lib/oauth';

  let error = $state('');

  onMount(async () => {
    try {
      // Generate PKCE values
      const verifier = await generateCodeVerifier();
      const challenge = await generateCodeChallenge(verifier);
      const state = generateState();

      // Store PKCE values for callback verification
      storePKCE(verifier, state);

      // Redirect to OpenKey authorization endpoint
      const authUrl = getAuthorizationUrl(state, challenge);
      window.location.href = authUrl;
    } catch (err) {
      error = err instanceof Error ? err.message : 'Failed to initialize login';
    }
  });
</script>

<div class="flex min-h-[60vh] flex-col items-center justify-center">
  {#if error}
    <div class="w-full max-w-md rounded-xl border border-red-800 bg-red-900/20 p-6">
      <h2 class="mb-2 text-lg font-semibold text-red-400">Login Error</h2>
      <p class="mb-4 text-surface-300">{error}</p>
      <a
        href="/"
        class="inline-flex items-center justify-center rounded-lg border border-surface-700 bg-transparent px-4 py-2 text-sm font-medium text-surface-300 transition-colors hover:border-surface-500 hover:text-surface-50"
      >
        Back to Home
      </a>
    </div>
  {:else}
    <div class="text-center">
      <div class="mb-4 h-8 w-8 animate-spin rounded-full border-2 border-primary-600 border-t-transparent mx-auto"></div>
      <p class="text-surface-400">Redirecting to OpenKey...</p>
    </div>
  {/if}
</div>
