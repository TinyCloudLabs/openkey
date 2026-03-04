<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import Card from '$lib/components/ui/card.svelte';

  const session = authClient.useSession();

  const SECRETS_APP_URL = 'https://secrets.tinycloud.xyz';

  $effect(() => {
    if (!$session.isPending) {
      if (!$session.data) {
        goto('/auth/login');
      }
    }
  });
</script>

<div class="mx-auto max-w-3xl px-4 py-8">
  <div class="mb-6">
    <a href="/dashboard" class="text-sm text-surface-500 hover:text-surface-700 transition-colors">
      &larr; Back to Dashboard
    </a>
  </div>

  <header class="mb-8">
    <h1 class="text-3xl font-bold text-surface-900">Secrets & Variables</h1>
    <p class="mt-1 text-surface-500">Store and manage secrets and environment variables</p>
  </header>

  <Card>
    <div class="py-12 text-center">
      <div class="mb-4">
        <svg xmlns="http://www.w3.org/2000/svg" class="mx-auto h-12 w-12 text-surface-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
          <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
        </svg>
      </div>
      <h2 class="text-xl font-semibold text-surface-900 mb-2">Secrets Management Has Moved</h2>
      <p class="text-surface-500 mb-6 max-w-md mx-auto">
        Secrets and variables are now managed through the TinyCloud Secrets app with end-to-end encryption powered by your OpenKey wallet.
      </p>
      <a
        href={SECRETS_APP_URL}
        class="inline-flex items-center gap-2 rounded-xl bg-surface-900 px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-surface-800"
      >
        Go to TinyCloud Secrets
        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
        </svg>
      </a>
    </div>
  </Card>
</div>
