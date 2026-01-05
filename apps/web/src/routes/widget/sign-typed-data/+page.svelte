<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  const session = authClient.useSession();

  let typedData = $state<{
    domain: any;
    types: any;
    primaryType: string;
    message: any;
  } | null>(null);
  let keyId = $state<string | null>(null);
  let key = $state<EthereumKey | null>(null);
  let loading = $state(true);
  let signing = $state(false);
  let error = $state('');

  const origin = $page.url.searchParams.get('origin') || '*';

  onMount(async () => {
    window.addEventListener('message', handleMessage);

    if ($session.data) {
      loading = false;
    }
  });

  async function handleMessage(event: MessageEvent) {
    if (event.data?.type === 'openkey:signTypedData:request') {
      typedData = event.data.data;
      keyId = event.data.data?.keyId || null;

      if (keyId && $session.data) {
        try {
          const result = await api.getKey(keyId);
          key = result.key;
        } catch {
          // Key not found
        }
      }
    }
  }

  async function signTypedData() {
    if (!key || !typedData) return;

    signing = true;
    error = '';

    try {
      const result = await api.signTypedData(key.id, typedData);
      sendResponse({
        type: 'openkey:signTypedData:response',
        success: true,
        signature: result.signature,
        address: result.address,
      });
      sendClose();
    } catch (e: any) {
      error = e.message || 'Signing failed';
    } finally {
      signing = false;
    }
  }

  function cancel() {
    sendResponse({
      type: 'openkey:signTypedData:response',
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
    <h1 class="text-xl font-semibold text-surface-50">Sign Typed Data</h1>
    <button
      class="bg-transparent border-none text-surface-400 text-2xl cursor-pointer p-0 leading-none hover:text-surface-50 transition-colors"
      onclick={cancel}
    >
      &times;
    </button>
  </header>

  {#if !$session.data}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p class="mb-4">Sign in to sign data</p>
      <Button href="/auth/login">Sign In</Button>
    </div>
  {:else if loading}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      Loading...
    </div>
  {:else if !key}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p>Please connect first to sign data.</p>
    </div>
  {:else if !typedData}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p>No data to sign.</p>
    </div>
  {:else}
    <div class="flex flex-col gap-4 flex-1">
      <Card class="p-4">
        <span class="block text-surface-400 text-xs uppercase mb-2">Signing with:</span>
        <span class="font-semibold mr-2">{key.label || `Key ${key.keyIndex}`}</span>
        <code class="font-mono text-surface-400 text-sm">{formatAddress(key.address)}</code>
      </Card>

      <Card class="p-4">
        <span class="block text-surface-400 text-xs uppercase mb-2">Domain:</span>
        <pre class="m-0 whitespace-pre-wrap break-all font-mono text-xs max-h-[120px] overflow-y-auto">{JSON.stringify(typedData.domain, null, 2)}</pre>
      </Card>

      <Card class="p-4">
        <span class="block text-surface-400 text-xs uppercase mb-2">{typedData.primaryType}:</span>
        <pre class="m-0 whitespace-pre-wrap break-all font-mono text-xs max-h-[120px] overflow-y-auto">{JSON.stringify(typedData.message, null, 2)}</pre>
      </Card>

      {#if error}
        <Card class="bg-red-500/10 border-red-500 text-red-500 p-4">
          {error}
        </Card>
      {/if}

      <div class="flex gap-3 mt-auto">
        <Button variant="secondary" class="flex-1" onclick={cancel}>Cancel</Button>
        <Button class="flex-1" onclick={signTypedData} disabled={signing}>
          {signing ? 'Signing...' : 'Sign Data'}
        </Button>
      </div>
    </div>
  {/if}
</div>
