<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
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
  let fetched = $state(false);

  // Get OAuth parameters from URL
  const clientId = $page.url.searchParams.get('client_id');
  const scope = $page.url.searchParams.get('scope') || 'openid';

  // Extract signed query params (up to and including sig) for consent endpoint
  function getOAuthQuery(): string | undefined {
    const params = new URLSearchParams(window.location.search);
    if (!params.has('sig')) return undefined;
    const signed = new URLSearchParams();
    for (const [key, value] of params.entries()) {
      signed.append(key, value);
      if (key === 'sig') break;
    }
    return signed.toString();
  }

  async function fetchClientInfo() {
    if (!clientId) {
      error = 'Missing client_id';
      loading = false;
      return;
    }
    try {
      const res = await fetch(
        `${API_BASE}/api/auth/oauth2/public-client?client_id=${encodeURIComponent(clientId)}`,
        { credentials: 'include' }
      );
      if (res.ok) {
        const data = await res.json();
        clientInfo = {
          name: data.client_name || data.name || 'Unknown',
          uri: data.client_uri || data.uri,
          icon: data.logo_uri || data.icon,
        };
      } else {
        const data = await res.json().catch(() => null);
        error = data?.message || `Failed to load application (${res.status})`;
      }
    } catch (e: unknown) {
      error = 'Failed to load application info';
    }
    loading = false;
  }

  // Wait for session to resolve, then either redirect or fetch client info
  $effect(() => {
    if ($session.isPending || fetched) return;

    if (!$session.data) {
      const returnUrl = encodeURIComponent($page.url.pathname + $page.url.search);
      goto(`/auth/login?redirect=${returnUrl}`);
      return;
    }

    // Session is resolved and user is authenticated - fetch client info
    fetched = true;
    fetchClientInfo();
  });

  async function handleConsent(accept: boolean) {
    submitting = true;
    error = '';

    try {
      const res = await fetch(`${API_BASE}/api/auth/oauth2/consent`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accept, oauth_query: getOAuthQuery() }),
      });

      const result = await res.json();

      if (!res.ok) {
        error = result?.message || 'Consent failed';
        submitting = false;
        return;
      }

      // Redirect to the URI returned by the consent endpoint
      if (result?.uri) {
        window.location.href = result.uri;
      } else if (result?.redirect) {
        window.location.href = result.redirect;
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

<div class="min-h-screen bg-surface-50 flex items-center justify-center px-4">
  <Card class="w-full max-w-md">
    {#if loading}
      <div class="py-12 text-center text-surface-500">
        Loading...
      </div>
    {:else if error && !clientInfo}
      <div class="py-12 text-center">
        <div class="text-red-600 mb-4">{error}</div>
        <a href="/" class="text-primary-600 hover:text-primary-700">Return home</a>
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
          <div class="w-16 h-16 rounded-lg bg-surface-100 mx-auto mb-4 flex items-center justify-center">
            <span class="text-2xl text-surface-500">
              {clientInfo.name.charAt(0).toUpperCase()}
            </span>
          </div>
        {/if}

        <h1 class="text-xl font-bold text-surface-900 mb-2">
          {clientInfo.name}
        </h1>

        {#if clientInfo.uri}
          <a
            href={clientInfo.uri}
            target="_blank"
            rel="noopener noreferrer"
            class="text-sm text-surface-500 hover:text-surface-700"
          >
            {clientInfo.uri}
          </a>
        {/if}
      </div>

      <div class="border-t border-surface-200 pt-6 mb-6">
        <p class="text-surface-600 mb-4 text-center">
          wants to verify your identity
        </p>

        <div class="bg-surface-100 rounded-lg p-4">
          <h3 class="text-sm font-semibold text-surface-500 uppercase tracking-wide mb-2">
            This will allow the app to:
          </h3>
          <ul class="space-y-2">
            <li class="flex items-center gap-2 text-surface-700">
              <svg class="w-4 h-4 text-primary-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
              Verify your OpenKey identity
            </li>
          </ul>
        </div>
      </div>

      {#if error}
        <div class="text-red-600 text-sm text-center mb-4">{error}</div>
      {/if}

      <div class="flex flex-col gap-3">
        <Button onclick={allow} disabled={submitting}>
          {submitting ? 'Processing...' : 'Allow'}
        </Button>
        <Button variant="secondary" onclick={deny} disabled={submitting}>
          Deny
        </Button>
      </div>

      <p class="text-xs text-surface-400 text-center mt-6">
        Signed in as {$session.data?.user?.email}
      </p>
    {/if}
  </Card>
</div>
