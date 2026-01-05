<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { onMount } from 'svelte';

  const session = authClient.useSession();

  let keys = $state<EthereumKey[]>([]);
  let loading = $state(true);
  let generating = $state(false);
  let error = $state('');

  // Redirect if not logged in
  $effect(() => {
    if (!$session.isPending && !$session.data) {
      goto('/auth/login');
    }
  });

  onMount(async () => {
    await loadKeys();
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

<div class="dashboard">
  <div class="header">
    <div>
      <h1>Dashboard</h1>
      {#if $session.data}
        <p class="email">{$session.data.user.email}</p>
      {/if}
    </div>
    <button class="button secondary" onclick={signOut}>Sign Out</button>
  </div>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <div class="section">
    <div class="section-header">
      <h2>Your Keys</h2>
      <button class="button primary" onclick={generateKey} disabled={generating}>
        {generating ? 'Generating...' : '+ Generate Key'}
      </button>
    </div>

    {#if loading}
      <div class="loading">Loading keys...</div>
    {:else if keys.length === 0}
      <div class="empty">
        <p>No keys yet. Generate your first Ethereum key.</p>
      </div>
    {:else}
      <div class="keys-list">
        {#each keys as key}
          <div class="key-card">
            <div class="key-info">
              <div class="key-label">{key.label || `Key ${key.keyIndex}`}</div>
              <div class="key-address">
                <code>{formatAddress(key.address)}</code>
                <button class="copy-btn" onclick={() => copyAddress(key.address)} title="Copy address">
                  Copy
                </button>
              </div>
            </div>
            <a href="/dashboard/keys/{key.id}" class="button secondary small">
              Manage
            </a>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>

<style>
  .dashboard {
    max-width: 800px;
    margin: 0 auto;
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 2rem;
  }

  h1 {
    margin: 0 0 0.5rem 0;
  }

  .email {
    color: #888;
    margin: 0;
  }

  .section {
    background: #1a1a1a;
    border: 1px solid #333;
    border-radius: 12px;
    padding: 1.5rem;
  }

  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }

  .section-header h2 {
    margin: 0;
  }

  .keys-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .key-card {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    background: #0a0a0a;
    border: 1px solid #333;
    border-radius: 8px;
  }

  .key-label {
    font-weight: 600;
    margin-bottom: 0.25rem;
  }

  .key-address {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .key-address code {
    font-family: 'SF Mono', Monaco, monospace;
    color: #888;
    font-size: 0.875rem;
  }

  .copy-btn {
    background: transparent;
    border: 1px solid #333;
    color: #888;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.75rem;
  }

  .copy-btn:hover {
    border-color: #666;
    color: #fafafa;
  }

  .button {
    padding: 0.75rem 1.5rem;
    border: none;
    border-radius: 8px;
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    transition: all 0.2s;
  }

  .button.small {
    padding: 0.5rem 1rem;
  }

  .button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .button.primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
  }

  .button.secondary {
    background: transparent;
    border: 1px solid #333;
    color: #fafafa;
  }

  .loading, .empty {
    text-align: center;
    padding: 2rem;
    color: #888;
  }

  .error {
    background: rgba(255, 68, 68, 0.1);
    border: 1px solid #ff4444;
    color: #ff4444;
    padding: 1rem;
    border-radius: 8px;
    margin-bottom: 1rem;
  }
</style>
