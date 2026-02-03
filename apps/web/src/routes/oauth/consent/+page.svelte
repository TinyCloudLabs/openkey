<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { authClient, API_BASE } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  const session = authClient.useSession();

  let clientInfo = $state<{
    name: string;
    uri?: string;
    icon?: string;
  } | null>(null);
  let loading = $state(true);
  let submitting = $state(false);
  let error = $state('');

  // Get OAuth parameters from URL
  const clientId = $page.url.searchParams.get('client_id');
  const scope = $page.url.searchParams.get('scope') || 'openid';

  onMount(async () => {
    // Redirect to login if not authenticated
    if (!$session.isPending && !$session.data) {
      const returnUrl = encodeURIComponent($page.url.pathname + $page.url.search);
      goto(`/auth/login?redirect=${returnUrl}`);
      return;
    }

    // Fetch client info via direct API call
    if (clientId) {
      try {
        const res = await fetch(`${API_BASE}/api/auth/oauth2/public-client?client_id=${encodeURIComponent(clientId)}`, {
          credentials: 'include',
        });
        if (res.ok) {
          const data = await res.json();
          clientInfo = {
            name: data.name,
            uri: data.uri,
            icon: data.icon,
          };
        } else {
          error = 'Unknown application';
        }
      } catch (e: unknown) {
        error = 'Failed to load application info';
      }
    } else {
      error = 'Missing client_id';
    }

    loading = false;
  });

  // Re-check auth when session changes
  $effect(() => {
    if (!$session.isPending && !$session.data && !loading) {
      const returnUrl = encodeURIComponent($page.url.pathname + $page.url.search);
      goto(`/auth/login?redirect=${returnUrl}`);
    }
  });

  async function handleConsent(accept: boolean) {
    submitting = true;
    error = '';

    try {
      const res = await fetch(`${API_BASE}/api/auth/oauth2/consent`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          accept,
          oauth_query: window.location.search.substring(1),
        }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        error = data.message || data.error || 'Consent failed';
        submitting = false;
        return;
      }

      const data = await res.json();

      // Redirect to the URI returned by the consent endpoint
      if (data.uri) {
        window.location.href = data.uri;
      } else if (data.redirect && data.url) {
        window.location.href = data.url;
      }
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : 'An error occurred';
      submitting = false;
    }
  }

  function deny() {
    handleConsent(false);
  }

  function allow() {
    handleConsent(true);
  }
</script>

<div class="min-h-screen bg-surface-950 flex items-center justify-center px-4">
  <Card class="w-full max-w-md">
    {#if loading || $session.isPending}
      <div class="py-12 text-center text-surface-400">
        Loading...
      </div>
    {:else if error && !clientInfo}
      <div class="py-12 text-center">
        <div class="text-red-400 mb-4">{error}</div>
        <a href="/" class="text-primary-400 hover:text-primary-300">Return home</a>
      </div>
    {:else if clientInfo}
      <div class="text-center mb-6">
        {#if clientInfo.icon}
          <img
            src={clientInfo.icon}
            alt={clientInfo.name}
            class="w-16 h-16 rounded-lg mx-auto mb-4"
          />
        {:else}
          <div class="w-16 h-16 rounded-lg bg-surface-800 mx-auto mb-4 flex items-center justify-center">
            <span class="text-2xl text-surface-400">
              {clientInfo.name.charAt(0).toUpperCase()}
            </span>
          </div>
        {/if}

        <h1 class="text-xl font-bold text-surface-50 mb-2">
          {clientInfo.name}
        </h1>

        {#if clientInfo.uri}
          <a
            href={clientInfo.uri}
            target="_blank"
            rel="noopener noreferrer"
            class="text-sm text-surface-400 hover:text-surface-300"
          >
            {clientInfo.uri}
          </a>
        {/if}
      </div>

      <div class="border-t border-surface-700 pt-6 mb-6">
        <p class="text-surface-300 mb-4 text-center">
          wants to verify your identity
        </p>

        <div class="bg-surface-800 rounded-lg p-4">
          <h3 class="text-sm font-semibold text-surface-400 uppercase tracking-wide mb-2">
            This will allow the app to:
          </h3>
          <ul class="space-y-2">
            <li class="flex items-center gap-2 text-surface-200">
              <svg class="w-4 h-4 text-primary-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
              Verify your OpenKey identity
            </li>
          </ul>
        </div>
      </div>

      {#if error}
        <div class="text-red-400 text-sm text-center mb-4">{error}</div>
      {/if}

      <div class="flex flex-col gap-3">
        <Button onclick={allow} disabled={submitting}>
          {submitting ? 'Processing...' : 'Allow'}
        </Button>
        <Button variant="secondary" onclick={deny} disabled={submitting}>
          Deny
        </Button>
      </div>

      <p class="text-xs text-surface-500 text-center mt-6">
        Signed in as {$session.data?.user?.email}
      </p>
    {/if}
  </Card>
</div>
