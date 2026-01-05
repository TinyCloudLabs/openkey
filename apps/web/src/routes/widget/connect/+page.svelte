<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

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

<div class="flex-1 flex flex-col">
  <header class="flex justify-between items-center mb-6">
    <h1 class="text-xl font-semibold text-surface-50">Connect to {appName || 'App'}</h1>
    <button
      class="bg-transparent border-none text-surface-400 text-2xl cursor-pointer p-0 leading-none hover:text-surface-50 transition-colors"
      onclick={cancel}
    >
      &times;
    </button>
  </header>

  {#if !$session.data}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p class="mb-4">Sign in to connect your OpenKey wallet</p>
      <Button href="/auth/login?redirect=/widget/connect?origin={encodeURIComponent(origin)}">
        Sign In
      </Button>
    </div>
  {:else if loading}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      Loading your keys...
    </div>
  {:else if error}
    <Card class="bg-red-500/10 border-red-500 text-red-500">
      {error}
    </Card>
  {:else if keys.length === 0}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p class="mb-4">No keys found. Generate your first key to connect.</p>
      <Button onclick={generateAndSelect}>
        Generate Key
      </Button>
    </div>
  {:else}
    <div class="flex flex-col gap-3">
      <p class="text-surface-400 mb-2">Select a key to connect:</p>
      {#each keys as key}
        <button
          class="flex justify-between items-center p-4 bg-surface-900 border border-surface-700 rounded-lg text-surface-50 cursor-pointer transition-all hover:border-primary-500"
          onclick={() => selectKey(key)}
        >
          <span class="font-semibold">{key.label || `Key ${key.keyIndex}`}</span>
          <code class="font-mono text-surface-400 text-sm">{formatAddress(key.address)}</code>
        </button>
      {/each}
      <Button variant="secondary" onclick={generateAndSelect}>
        + Generate New Key
      </Button>
    </div>
  {/if}
</div>
