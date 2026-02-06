<script lang="ts">
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  const session = authClient.useSession();

  let loading = $state(false);
  let linking = $state(false);
  let error = $state('');
  let connectedAddress = $state('');
  let initialized = $state(false);
  let requestReceived = $state(false);

  const origin = $page.url.searchParams.get('origin') || '*';

  // Use $effect instead of onMount for Svelte 5 compatibility with SSR disabled
  // onMount doesn't fire when ssr=false in SvelteKit, but $effect does
  $effect(() => {
    if (typeof window !== 'undefined' && !initialized) {
      initialized = true;

      // Listen for incoming messages
      window.addEventListener('message', handleMessage);

      // Notify parent that widget is ready (AFTER listener is set up)
      const targetOrigin = new URL(window.location.href).searchParams.get('origin') || '*';
      if (window.opener) {
        window.opener.postMessage({ type: 'openkey:ready' }, targetOrigin);
      } else if (window.parent !== window) {
        window.parent.postMessage({ type: 'openkey:ready' }, targetOrigin);
      }
    }
  });

  function handleMessage(event: MessageEvent) {
    if (event.data?.type === 'openkey:link-wallet:request') {
      requestReceived = true;
    }
  }

  async function connectAndLink() {
    if (!window.ethereum) {
      error = 'MetaMask or compatible wallet not detected. Please install MetaMask and try again.';
      return;
    }

    linking = true;
    error = '';

    try {
      // Step 1: Connect to MetaMask
      const accounts: string[] = await window.ethereum.request({ method: 'eth_requestAccounts' });
      if (!accounts || accounts.length === 0) {
        throw new Error('No accounts returned from wallet');
      }
      const account = accounts[0];
      connectedAddress = account;

      // Step 2: Get challenge from server
      const challenge = await api.getLinkChallenge();

      // Step 3: Sign challenge with MetaMask
      const signature: string = await window.ethereum.request({
        method: 'personal_sign',
        params: [challenge.message, account],
      });

      // Step 4: Submit to API
      const result = await api.linkWallet({
        address: account,
        signature,
        message: challenge.message,
      });

      // Step 5: Send success response to parent
      sendResponse({
        type: 'openkey:link-wallet:response',
        success: true,
        address: account,
        keyId: result.key.id,
      });
      sendClose();
    } catch (e: any) {
      // MetaMask user rejection
      if (e.code === 4001) {
        error = 'Wallet connection was rejected.';
      } else {
        error = e.message || 'Failed to link wallet';
      }
    } finally {
      linking = false;
    }
  }

  function cancel() {
    sendResponse({
      type: 'openkey:link-wallet:response',
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
    <h1 class="text-xl font-semibold text-surface-50">Link Your Wallet</h1>
    <button
      class="bg-transparent border-none text-surface-400 text-2xl cursor-pointer p-0 leading-none hover:text-surface-50 transition-colors"
      onclick={cancel}
    >
      &times;
    </button>
  </header>

  {#if !$session.data}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p class="mb-4">Sign in to link your external wallet</p>
      <Button href="/auth/login?redirect=/widget/link-wallet?origin={encodeURIComponent(origin)}">
        Sign In
      </Button>
    </div>
  {:else if connectedAddress && !linking && !error}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p>Wallet linked successfully.</p>
      <code class="font-mono text-surface-50 text-sm mt-2">{formatAddress(connectedAddress)}</code>
    </div>
  {:else}
    <div class="flex flex-col gap-4 flex-1">
      <p class="text-surface-400">
        Connect an external wallet (e.g. MetaMask) to link it to your OpenKey account. You'll be asked to sign a verification message.
      </p>

      {#if error}
        <Card class="bg-red-500/10 border-red-500 text-red-500 p-4">
          {error}
        </Card>
      {/if}

      <div class="flex gap-3 mt-auto">
        <Button variant="secondary" class="flex-1" onclick={cancel}>Cancel</Button>
        <Button class="flex-1" onclick={connectAndLink} disabled={linking}>
          {linking ? 'Linking...' : 'Connect Wallet'}
        </Button>
      </div>
    </div>
  {/if}
</div>
