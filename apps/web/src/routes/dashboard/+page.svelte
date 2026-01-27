<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  const session = authClient.useSession();

  let keys = $state<EthereumKey[]>([]);
  let loading = $state(true);
  let generating = $state(false);
  let error = $state('');

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

  function copyAddress(address: string) {
    navigator.clipboard.writeText(address);
  }
</script>

<div class="mx-auto max-w-3xl px-4 py-8">
  <header class="mb-8 flex items-start justify-between">
    <div>
      <h1 class="text-3xl font-bold text-surface-50">Dashboard</h1>
      {#if $session.data}
        <p class="mt-1 text-sm text-surface-400">{$session.data.user.email}</p>
      {/if}
    </div>
    <div class="flex items-center gap-3">
      <a
        href="/dashboard/settings"
        class="inline-flex h-9 items-center justify-center rounded-lg border border-surface-700 bg-surface-800 px-3 text-sm font-medium text-surface-50 transition-colors hover:bg-surface-700"
      >
        Settings
      </a>
      <Button variant="secondary" onclick={signOut}>Sign Out</Button>
    </div>
  </header>

  {#if error}
    <div class="mb-6 rounded-lg border border-red-500/50 bg-red-500/10 p-4 text-red-400">
      {error}
    </div>
  {/if}

  <Card>
    <div class="mb-6 flex items-center justify-between">
      <h2 class="text-xl font-semibold text-surface-50">Your Keys</h2>
      <Button onclick={generateKey} disabled={generating}>
        {generating ? 'Generating...' : '+ Generate Key'}
      </Button>
    </div>

    {#if loading}
      <div class="py-12 text-center text-surface-400">
        <p>Loading keys...</p>
      </div>
    {:else if keys.length === 0}
      <div class="py-12 text-center text-surface-400">
        <p>No keys yet. Generate your first Ethereum key.</p>
      </div>
    {:else}
      <div class="flex flex-col gap-3">
        {#each keys as key}
          <div class="flex items-center justify-between rounded-lg border border-surface-800 bg-surface-950 p-4">
            <div>
              <div class="font-semibold text-surface-50">
                {key.label || `Key ${key.keyIndex}`}
              </div>
              <div class="mt-1 flex items-center gap-2">
                <code class="font-mono text-sm text-surface-400">{formatAddress(key.address)}</code>
                <button
                  class="rounded border border-surface-700 px-2 py-0.5 text-xs text-surface-400 transition-colors hover:border-surface-500 hover:text-surface-200"
                  onclick={() => copyAddress(key.address)}
                  title="Copy address"
                >
                  Copy
                </button>
              </div>
            </div>
            <a
              href="/dashboard/keys/{key.id}"
              class="inline-flex h-9 items-center justify-center rounded-lg border border-surface-700 bg-surface-800 px-3 text-sm font-medium text-surface-50 transition-colors hover:bg-surface-700"
            >
              Manage
            </a>
          </div>
        {/each}
      </div>
    {/if}
  </Card>
</div>
