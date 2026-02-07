<script lang="ts">
  import { page } from '$app/stores';
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
  let keysLoaded = $state(false);
  let initialized = $state(false);
  let contentEl = $state<HTMLDivElement | undefined>(undefined);

  const origin = $page.url.searchParams.get('origin') || '*';

  $effect(() => {
    if (typeof window !== 'undefined' && !initialized) {
      initialized = true;

      window.addEventListener('message', handleMessage);

      const targetOrigin = new URL(window.location.href).searchParams.get('origin') || '*';
      window.parent.postMessage({ type: 'openkey:ready' }, targetOrigin);
    }
  });

  // ResizeObserver to notify parent of height changes
  $effect(() => {
    if (!contentEl) return;
    const observer = new ResizeObserver(entries => {
      const height = entries[0].contentRect.height;
      window.parent.postMessage({ type: 'openkey:resize', height }, '*');
    });
    observer.observe(contentEl);
    return () => observer.disconnect();
  });

  // Reactively load keys when session becomes available
  $effect(() => {
    if ($session.data && !keysLoaded) {
      keysLoaded = true;
      loadKeys();
    }
  });

  function handleMessage(event: MessageEvent) {
    if (event.data?.type === 'openkey:auth:request') {
      appName = event.data.appName || 'Unknown App';
    }
    if (event.data?.type === 'openkey:link-wallet:result') {
      if (event.data.success) {
        // Refresh key list after successful wallet link
        keysLoaded = false;
        loadKeys().then(() => { keysLoaded = true; });
      }
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
      keyType: key.keyType,
    });
  }

  function linkWallet() {
    // In embed mode, delegate wallet linking to parent SDK
    window.parent.postMessage({ type: 'openkey:link-wallet:delegate' }, origin);
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
    window.parent.postMessage(data, origin);
  }

  function sendClose() {
    window.parent.postMessage({ type: 'openkey:close' }, origin);
  }

  function formatAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }
</script>

<div bind:this={contentEl} class="flex flex-col gap-3">
  <header class="flex justify-between items-center mb-2">
    <h1 class="text-lg font-semibold text-surface-50">Connect to {appName || 'App'}</h1>
  </header>

  {#if !$session.data}
    <div class="flex flex-col items-center justify-center text-center text-surface-400 py-4">
      <p class="mb-3 text-sm">Sign in to connect your OpenKey wallet</p>
      <Button href="/auth/login?redirect=/widget/embed/connect?origin={encodeURIComponent(origin)}">
        Sign In
      </Button>
    </div>
  {:else if loading}
    <div class="flex flex-col items-center justify-center text-center text-surface-400 py-4">
      Loading your keys...
    </div>
  {:else if error}
    <Card class="bg-red-500/10 border-red-500 text-red-500 p-3 text-sm">
      {error}
    </Card>
  {:else if keys.length === 0}
    <div class="flex flex-col items-center justify-center text-center text-surface-400 py-4">
      <p class="mb-3 text-sm">No keys found. Generate your first key to connect.</p>
      <Button onclick={generateAndSelect}>
        Generate Key
      </Button>
    </div>
  {:else}
    <div class="flex flex-col gap-2">
      <p class="text-surface-400 text-sm mb-1">Select a key to connect:</p>
      {#each keys as key}
        <button
          class="flex justify-between items-center p-3 bg-surface-900 border border-surface-700 rounded-lg text-surface-50 cursor-pointer transition-all hover:border-primary-500"
          onclick={() => selectKey(key)}
        >
          <span class="font-semibold text-sm flex items-center gap-2">
            {key.label || `Key ${key.keyIndex}`}
            {#if key.keyType === 'EXTERNAL'}
              <span class="text-xs font-medium px-1.5 py-0.5 rounded bg-surface-700 text-surface-300">(External)</span>
            {/if}
          </span>
          <code class="font-mono text-surface-400 text-xs">{formatAddress(key.address)}</code>
        </button>
      {/each}
      <Button variant="secondary" size="sm" onclick={generateAndSelect}>
        + Generate New Key
      </Button>
      <Button variant="secondary" size="sm" onclick={linkWallet}>
        Link New Wallet
      </Button>
    </div>
  {/if}
</div>
