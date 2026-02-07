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
  let signingIn = $state(false);

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
    window.location.href = '/widget/link-wallet?origin=' + encodeURIComponent(origin);
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

  async function signInWithPasskey() {
    signingIn = true;
    error = '';
    try {
      const result = await authClient.signIn.passkey();
      if (result.error) {
        error = result.error.message || 'Passkey sign-in failed';
      }
    } catch (e: any) {
      error = e.message || 'Passkey sign-in failed';
    } finally {
      signingIn = false;
    }
  }
</script>

<div class="min-h-screen bg-[#fafafa] flex flex-col items-center justify-center px-4 py-8">
  <div class="w-full max-w-sm flex flex-col items-center gap-6">
    <!-- Logo mark -->
    <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-surface-800 to-surface-900 flex items-center justify-center shadow-sm">
      <svg class="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
      </svg>
    </div>

    <!-- Main card -->
    <Card class="w-full p-6">
      <header class="flex justify-between items-center mb-5">
        <h1 class="text-lg font-semibold text-surface-900">Connect to {appName || 'App'}</h1>
        <button
          class="bg-transparent border-none text-surface-400 text-xl cursor-pointer p-1 leading-none hover:text-surface-600 transition-colors rounded-lg hover:bg-surface-100"
          onclick={cancel}
          aria-label="Close"
        >
          <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </header>

      {#if !$session.data}
        <div class="flex flex-col items-center justify-center text-center py-4">
          <p class="text-surface-500 text-sm mb-5">Sign in with your passkey to continue</p>

          {#if error}
            <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
              {error}
            </div>
          {/if}

          <Button onclick={signInWithPasskey} disabled={signingIn} class="w-full rounded-xl">
            {signingIn ? 'Signing in...' : 'Sign in with Passkey'}
          </Button>
        </div>
      {:else if loading}
        <div class="flex flex-col items-center justify-center text-center text-surface-400 py-8">
          <svg class="w-6 h-6 animate-spin text-surface-400 mb-3" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
          </svg>
          <span class="text-sm text-surface-500">Loading your keys...</span>
        </div>
      {:else if error}
        <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl text-sm" role="alert">
          {error}
        </div>
      {:else if keys.length === 0}
        <div class="flex flex-col items-center justify-center text-center py-4">
          <p class="text-surface-500 text-sm mb-5">No keys found. Generate your first key to connect.</p>
          <Button onclick={generateAndSelect} class="w-full rounded-xl">
            Generate Key
          </Button>
        </div>
      {:else}
        <div class="flex flex-col gap-3">
          <p class="text-surface-500 text-sm">Select a key to connect:</p>
          {#each keys as key}
            <button
              class="flex justify-between items-center p-4 bg-white border border-surface-200 rounded-xl text-surface-900 cursor-pointer transition-all hover:border-surface-900 hover:bg-surface-50 group"
              class:border-surface-900={selectedKey?.id === key.id}
              class:bg-surface-50={selectedKey?.id === key.id}
              onclick={() => selectKey(key)}
            >
              <span class="font-medium flex items-center gap-2">
                {key.label || `Key ${key.keyIndex}`}
                {#if key.keyType === 'EXTERNAL'}
                  <span class="text-xs font-medium px-1.5 py-0.5 rounded-md bg-surface-100 text-surface-500">(External)</span>
                {/if}
              </span>
              <div class="flex items-center gap-2">
                <code class="font-mono text-surface-400 text-sm">{formatAddress(key.address)}</code>
                {#if selectedKey?.id === key.id}
                  <svg class="w-5 h-5 text-surface-900" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                {/if}
              </div>
            </button>
          {/each}
          <Button variant="secondary" onclick={generateAndSelect} class="rounded-xl">
            + Generate New Key
          </Button>
          <Button variant="secondary" onclick={linkWallet} class="rounded-xl">
            Link External Wallet
          </Button>
        </div>
      {/if}
    </Card>

    {#if $session.data}
      <button
        onclick={() => authClient.signOut()}
        class="text-xs text-surface-400 hover:text-surface-600 transition-colors bg-transparent border-none cursor-pointer"
      >
        Sign out
      </button>
    {:else}
      <div class="flex items-center gap-3 text-sm">
        <a href="/auth/register" class="text-surface-500 hover:text-surface-700 transition-colors">Register</a>
        <span class="text-surface-300">|</span>
        <a href="/auth/recover" class="text-surface-500 hover:text-surface-700 transition-colors">Recover account</a>
      </div>
    {/if}

    <!-- Trust badge -->
    <div class="flex items-center gap-1.5 text-surface-400">
      <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
      </svg>
      <span class="text-xs">Protected by TEE hardware security</span>
    </div>
  </div>
</div>
