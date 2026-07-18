<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { copyText } from '$lib/clipboard';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  const session = authClient.useSession();

  let keys = $state<EthereumKey[]>([]);
  let loading = $state(true);
  let generating = $state(false);
  let error = $state('');
  let copiedId = $state<string | null>(null);

  // Redirect if not logged in, load keys when session is ready
  $effect(() => {
    if (!$session.isPending) {
      if (!$session.data) {
        goto('/auth/login');
      } else if (keys.length === 0 && loading) {
        loadKeys();
      }
    }
  });

  async function loadKeys() {
    loading = true;
    error = '';
    try {
      const result = await api.listKeys();
      keys = result.keys;
    } catch (e: any) {
      error = e.message || 'Failed to load keys';
    } finally {
      loading = false;
    }
  }

  async function generateKey() {
    generating = true;
    error = '';
    try {
      await api.generateKey();
      await loadKeys();
    } catch (e: any) {
      error = e.message || 'Failed to generate key';
    } finally {
      generating = false;
    }
  }

  async function signOut() {
    await authClient.signOut();
    goto('/');
  }

  function formatAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }

  async function copyAddress(address: string, keyId: string) {
    if (!(await copyText(address))) {
      error = 'Failed to copy address. Select the address and copy it manually.';
      return;
    }

    error = '';
    copiedId = keyId;
    setTimeout(() => {
      if (copiedId === keyId) copiedId = null;
    }, 2000);
  }
</script>

<div class="mx-auto max-w-3xl px-4 py-10">
  <!-- Header -->
  <div class="mb-8">
    {#if $session.data}
      <h1 class="text-2xl font-semibold text-surface-900">
        Welcome back, {$session.data.user.name || $session.data.user.email}
      </h1>
      <p class="mt-1 text-sm text-surface-500">{$session.data.user.email}</p>
    {:else}
      <h1 class="text-2xl font-semibold text-surface-900">Dashboard</h1>
    {/if}
  </div>

  <!-- Actions row -->
  <div class="mb-8 flex items-center gap-3">
    <Button variant="secondary" size="sm" href="/dashboard/settings">Settings</Button>
    <Button variant="secondary" size="sm" onclick={signOut}>Sign Out</Button>
  </div>

  <!-- Error -->
  {#if error}
    <div class="mb-6 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-600">
      {error}
    </div>
  {/if}

  <!-- Key Management Card -->
  <Card>
    <div class="mb-6 flex items-center justify-between">
      <h2 class="text-2xl font-semibold text-surface-900">Your Keys</h2>
      <Button onclick={generateKey} disabled={generating}>
        {generating ? 'Generating...' : '+ Generate Key'}
      </Button>
    </div>

    {#if loading}
      <div class="py-12 text-center text-surface-500">
        <p>Loading keys...</p>
      </div>
    {:else if keys.length === 0}
      <div class="py-12 text-center">
        <p class="text-surface-500">No keys yet. Generate your first Ethereum key.</p>
      </div>
    {:else}
      <div class="flex flex-col gap-3">
        {#each keys as key, i}
          <div class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-surface-200 bg-white p-4">
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2">
                <span class="font-medium text-surface-900">
                  {key.label || `Key ${key.keyIndex}`}
                </span>
                {#if i === 0}
                  <span class="rounded-full bg-surface-100 px-2 py-0.5 text-xs font-medium text-surface-500">
                    Primary
                  </span>
                {/if}
              </div>
              <div class="mt-1.5 flex items-center gap-2">
                <code class="font-mono text-sm text-surface-400">{formatAddress(key.address)}</code>
                <button
                  class="text-surface-400 transition-colors hover:text-surface-900"
                  onclick={() => copyAddress(key.address, key.id)}
                  title="Copy full address"
                >
                  {#if copiedId === key.id}
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                    </svg>
                  {:else}
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                      <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z" />
                      <path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z" />
                    </svg>
                  {/if}
                </button>
              </div>
            </div>
            <Button variant="secondary" size="sm" href="/dashboard/keys/{key.id}">
              Manage
            </Button>
          </div>
        {/each}
      </div>
    {/if}
  </Card>

  <!-- API Keys Card -->
  <Card class="mt-6">
    <div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h2 class="text-xl font-semibold text-surface-900">Managed Accounts</h2>
        <p class="text-sm text-surface-500 mt-1">
          See which apps manage an account and transfer custody back to your OpenKey.
        </p>
      </div>
      <Button variant="secondary" href="/dashboard/managed-accounts">Review custody</Button>
    </div>
  </Card>

  <!-- API Keys Card -->
  <Card class="mt-6">
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold text-surface-900">Secrets & Variables</h2>
        <p class="text-sm text-surface-500 mt-1">
          Store and manage secrets and environment variables with encrypted storage.
        </p>
      </div>
      <Button variant="secondary" href="/dashboard/api-keys">
        Manage
      </Button>
    </div>
  </Card>
</div>
