<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';

  const session = authClient.useSession();

  let keys = $state<EthereumKey[]>([]);
  let loading = $state(true);
  let appName = $state('');
  let selectedKey = $state<EthereumKey | null>(null);
  let error = $state('');

  const origin = $page.url.searchParams.get('origin') || '*';

  onMount(async () => {
    // Listen for incoming messages
    window.addEventListener('message', handleMessage);

    // Load keys if already authenticated
    if ($session.data) {
      await loadKeys();
    }
  });

  function handleMessage(event: MessageEvent) {
    if (event.data?.type === 'openkey:auth:request') {
      appName = event.data.appName || 'Unknown App';
    }
  }

  async function loadKeys() {
    loading = true;
    try {
      const result = await api.listKeys();
      keys = result.keys;
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  async function generateAndSelect() {
    loading = true;
    error = '';
    try {
      const { key } = await api.generateKey();
      selectKey(key);
    } catch (e: any) {
      error = e.message;
      loading = false;
    }
  }

  function selectKey(key: EthereumKey) {
    selectedKey = key;
    sendResponse({
      type: 'openkey:auth:response',
      success: true,
      address: key.address,
      keyId: key.id,
    });
  }

  function cancel() {
    sendResponse({
      type: 'openkey:auth:response',
      success: false,
      error: { code: 'USER_CANCELLED', message: 'User cancelled' },
    });
    sendClose();
  }

  function sendResponse(data: object) {
    if (window.opener) {
      window.opener.postMessage(data, origin);
    } else if (window.parent !== window) {
      window.parent.postMessage(data, origin);
    }
  }

  function sendClose() {
    const closeMsg = { type: 'openkey:close' };
    if (window.opener) {
      window.opener.postMessage(closeMsg, origin);
      window.close();
    } else if (window.parent !== window) {
      window.parent.postMessage(closeMsg, origin);
    }
  }

  function formatAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }
</script>

<div class="connect-widget">
  <header>
    <h1>Connect to {appName || 'App'}</h1>
    <button class="close-btn" onclick={cancel}>×</button>
  </header>

  {#if !$session.data}
    <div class="auth-needed">
      <p>Sign in to connect your OpenKey wallet</p>
      <a href="/auth/login?redirect=/widget/connect?origin={encodeURIComponent(origin)}" class="button primary">
        Sign In
      </a>
    </div>
  {:else if loading}
    <div class="loading">Loading your keys...</div>
  {:else if error}
    <div class="error">{error}</div>
  {:else if keys.length === 0}
    <div class="no-keys">
      <p>No keys found. Generate your first key to connect.</p>
      <button class="button primary" onclick={generateAndSelect}>
        Generate Key
      </button>
    </div>
  {:else}
    <div class="key-list">
      <p>Select a key to connect:</p>
      {#each keys as key}
        <button class="key-option" onclick={() => selectKey(key)}>
          <span class="key-label">{key.label || `Key ${key.keyIndex}`}</span>
          <code class="key-address">{formatAddress(key.address)}</code>
        </button>
      {/each}
      <button class="button secondary" onclick={generateAndSelect}>
        + Generate New Key
      </button>
    </div>
  {/if}
</div>

<style>
  .connect-widget {
    flex: 1;
    display: flex;
    flex-direction: column;
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }

  h1 {
    font-size: 1.25rem;
    margin: 0;
  }

  .close-btn {
    background: transparent;
    border: none;
    color: #888;
    font-size: 1.5rem;
    cursor: pointer;
    padding: 0;
    line-height: 1;
  }

  .close-btn:hover {
    color: #fafafa;
  }

  .auth-needed, .loading, .no-keys {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    color: #888;
  }

  .key-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .key-list p {
    color: #888;
    margin: 0 0 0.5rem 0;
  }

  .key-option {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    background: #1a1a1a;
    border: 1px solid #333;
    border-radius: 8px;
    color: #fafafa;
    cursor: pointer;
    transition: all 0.2s;
  }

  .key-option:hover {
    border-color: #667eea;
  }

  .key-label {
    font-weight: 600;
  }

  .key-address {
    font-family: 'SF Mono', Monaco, monospace;
    color: #888;
    font-size: 0.875rem;
  }

  .button {
    padding: 0.75rem 1.5rem;
    border: none;
    border-radius: 8px;
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    text-align: center;
    transition: all 0.2s;
  }

  .button.primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
  }

  .button.secondary {
    background: transparent;
    border: 1px solid #333;
    color: #888;
  }

  .button.secondary:hover {
    border-color: #666;
    color: #fafafa;
  }

  .error {
    background: rgba(255, 68, 68, 0.1);
    border: 1px solid #ff4444;
    color: #ff4444;
    padding: 1rem;
    border-radius: 8px;
  }
</style>
