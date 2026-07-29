<script lang="ts">
  import { onMount } from 'svelte';
  import { API_BASE } from '$lib/auth-client';

  let status = $state('Completing sign-in…');
  let error = $state('');

  onMount(async () => {
    if (!window.opener) {
      error = 'This sign-in window is no longer connected to OpenKey. Close it and try again.';
      return;
    }

    try {
      if (new URL(window.location.href).searchParams.has('error')) {
        throw new Error('The provider could not complete sign-in. Please try again.');
      }
      const response = await fetch(`${API_BASE}/api/auth/get-session`, {
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });
      const body = await response.json().catch(() => null);
      const sessionToken =
        response.headers.get('set-auth-token')
        || body?.session?.token
        || body?.token;
      if (!response.ok || !sessionToken) {
        throw new Error('OpenKey could not read the completed session. Please try again.');
      }

      window.opener.postMessage(
        { type: 'openkey:social:complete', sessionToken },
        window.location.origin,
      );
      status = 'Sign-in complete. You can close this window.';
      window.setTimeout(() => window.close(), 100);
    } catch (cause: any) {
      error = cause.message || 'Social sign-in failed.';
      window.opener.postMessage(
        { type: 'openkey:social:error', message: error },
        window.location.origin,
      );
    }
  });
</script>

<svelte:head>
  <title>Completing sign-in · OpenKey</title>
</svelte:head>

<div class="flex min-h-screen items-center justify-center bg-surface-50 px-4">
  <div class="w-full max-w-sm rounded-2xl border border-surface-200 bg-white p-8 text-center shadow-sm">
    <div class="mx-auto mb-5 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-surface-900 text-white">
      <svg class="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
      </svg>
    </div>
    {#if error}
      <h1 class="mb-2 text-lg font-semibold text-surface-900">Sign-in failed</h1>
      <p class="text-sm text-red-700" role="alert">{error}</p>
    {:else}
      <h1 class="mb-2 text-lg font-semibold text-surface-900">OpenKey</h1>
      <p class="text-sm text-surface-500" role="status">{status}</p>
    {/if}
  </div>
</div>
