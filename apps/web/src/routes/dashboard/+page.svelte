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
  let archivingId = $state<string | null>(null);
  let restoringId = $state<string | null>(null);
  let error = $state('');
  let copiedId = $state<string | null>(null);
  let activeKeys = $derived(keys.filter((key) => !key.archivedAt));
  let archivedKeys = $derived(keys.filter((key) => key.archivedAt));

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
      const result = await api.listKeys({ includeArchived: true });
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

  async function archiveKey(key: EthereumKey) {
    const confirmed = window.confirm('Archive this key? It will no longer appear during sign-in.');
    if (!confirmed) return;

    archivingId = key.id;
    error = '';
    try {
      await api.archiveKey(key.id);
      await loadKeys();
    } catch (e: any) {
      error = e.message || 'Failed to archive key';
    } finally {
      archivingId = null;
    }
  }

  async function restoreKey(key: EthereumKey) {
    restoringId = key.id;
    error = '';
    try {
      await api.unarchiveKey(key.id);
      await loadKeys();
    } catch (e: any) {
      error = e.message || 'Failed to restore key';
    } finally {
      restoringId = null;
    }
  }

  async function signOut() {
    await authClient.signOut();
    goto('/');
  }

  function formatAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }

  function formatDate(date: string): string {
    return new Date(date).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
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
    {:else if activeKeys.length === 0}
      <div class="py-12 text-center">
        <p class="text-surface-500">
          {archivedKeys.length > 0 ? 'No active keys. Restore an archived key or generate a new one.' : 'No keys yet. Generate your first Ethereum key.'}
        </p>
      </div>
    {:else}
      <div class="flex flex-col gap-3">
        {#each activeKeys as key, i}
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
            <div class="flex flex-wrap items-center gap-2">
              <Button variant="secondary" size="sm" href="/dashboard/keys/{key.id}">
                Manage
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onclick={() => archiveKey(key)}
                disabled={archivingId === key.id}
                class="border-red-200 text-red-600 hover:bg-red-50 hover:text-red-700"
              >
                {archivingId === key.id ? 'Archiving...' : 'Archive'}
              </Button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </Card>

  {#if !loading && archivedKeys.length > 0}
    <Card class="mt-6">
      <div class="mb-6">
        <h2 class="text-xl font-semibold text-surface-900">Archived Keys</h2>
        <p class="mt-1 text-sm text-surface-500">Archived keys are hidden during sign-in.</p>
      </div>

      <div class="flex flex-col gap-3">
        {#each archivedKeys as key}
          <div class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-surface-200 bg-surface-50 p-4">
            <div class="min-w-0 flex-1">
              <div class="flex flex-wrap items-center gap-2">
                <span class="font-medium text-surface-700">
                  {key.label || `Key ${key.keyIndex}`}
                </span>
                <span class="rounded-full bg-white px-2 py-0.5 text-xs font-medium text-surface-500">
                  Archived
                </span>
              </div>
              <div class="mt-1.5 flex flex-wrap items-center gap-2">
                <code class="font-mono text-sm text-surface-500">{formatAddress(key.address)}</code>
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
                {#if key.archivedAt}
                  <span class="text-sm text-surface-400">Archived {formatDate(key.archivedAt)}</span>
                {/if}
              </div>
            </div>
            <div class="flex flex-wrap items-center gap-2">
              <Button variant="secondary" size="sm" href="/dashboard/keys/{key.id}">
                Manage
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onclick={() => restoreKey(key)}
                disabled={restoringId === key.id}
              >
                {restoringId === key.id ? 'Restoring...' : 'Restore'}
              </Button>
            </div>
          </div>
        {/each}
      </div>
    </Card>
  {/if}

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
