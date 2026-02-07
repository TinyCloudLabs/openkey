<script lang="ts">
  import { page } from '$app/stores';
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
  let sessionChecked = $state(false);
  let keyFetched = $state(false);
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

  // Reactively update loading state when session becomes available
  $effect(() => {
    if ($session.data && !sessionChecked) {
      sessionChecked = true;
      loading = false;
    }
  });

  // Reactively fetch key when session becomes available and we have a keyId
  $effect(() => {
    if ($session.data && keyId && !keyFetched && !key) {
      keyFetched = true;
      api.getKey(keyId).then(result => {
        key = result.key;
      }).catch(() => {
        // Key not found
      });
    }
  });

  async function handleMessage(event: MessageEvent) {
    if (event.data?.type === 'openkey:signTypedData:request') {
      typedData = event.data.data;
      keyId = event.data.data?.keyId || null;
      keyFetched = false;

      if (keyId && $session.data) {
        try {
          const result = await api.getKey(keyId);
          key = result.key;
          keyFetched = true;
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
    <h1 class="text-lg font-semibold text-surface-50">Sign Typed Data</h1>
  </header>

  {#if !$session.data}
    <div class="flex flex-col items-center justify-center text-center text-surface-400 py-4">
      <p class="mb-3 text-sm">Sign in to sign data</p>
      <Button href="/auth/login?redirect=/widget/embed/sign-typed-data?origin={encodeURIComponent(origin)}">Sign In</Button>
    </div>
  {:else if loading}
    <div class="flex flex-col items-center justify-center text-center text-surface-400 py-4">
      Loading...
    </div>
  {:else if !key}
    <div class="flex flex-col items-center justify-center text-center text-surface-400 py-4">
      <p class="text-sm">Please connect first to sign data.</p>
    </div>
  {:else if !typedData}
    <div class="flex flex-col items-center justify-center text-center text-surface-400 py-4">
      <p class="text-sm">No data to sign.</p>
    </div>
  {:else}
    <div class="flex flex-col gap-3">
      <Card class="p-3">
        <span class="block text-surface-400 text-xs uppercase mb-1">Signing with:</span>
        <span class="font-semibold text-sm mr-2">{key.label || `Key ${key.keyIndex}`}</span>
        <code class="font-mono text-surface-400 text-xs">{formatAddress(key.address)}</code>
      </Card>

      <Card class="p-3">
        <span class="block text-surface-400 text-xs uppercase mb-1">Domain:</span>
        <pre class="m-0 whitespace-pre-wrap break-all font-mono text-xs max-h-[100px] overflow-y-auto">{JSON.stringify(typedData.domain, null, 2)}</pre>
      </Card>

      <Card class="p-3">
        <span class="block text-surface-400 text-xs uppercase mb-1">{typedData.primaryType}:</span>
        <pre class="m-0 whitespace-pre-wrap break-all font-mono text-xs max-h-[100px] overflow-y-auto">{JSON.stringify(typedData.message, null, 2)}</pre>
      </Card>

      {#if error}
        <Card class="bg-red-500/10 border-red-500 text-red-500 p-3 text-sm">
          {error}
        </Card>
      {/if}

      <div class="flex gap-2">
        <Button variant="secondary" size="sm" class="flex-1" onclick={cancel}>Cancel</Button>
        <Button size="sm" class="flex-1" onclick={signTypedData} disabled={signing}>
          {signing ? 'Signing...' : 'Sign Data'}
        </Button>
      </div>
    </div>
  {/if}
</div>
