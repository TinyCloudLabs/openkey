<script lang="ts">
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { isEmbedContext, embedSignInPasskey, clearSessionToken, getSessionToken, setSessionToken } from '$lib/embed-passkey';
  import Button from '$lib/components/ui/button.svelte';

  const session = authClient.useSession();
  const inIframe = typeof window !== 'undefined' && isEmbedContext();

  let keys = $state<EthereumKey[]>([]);
  let loading = $state(true);
  let appName = $state('');
  let selectedKey = $state<EthereumKey | null>(null);
  let error = $state('');
  let keysLoaded = $state(false);
  let initialized = $state(false);
  let contentEl = $state<HTMLDivElement | undefined>(undefined);
  let signingIn = $state(false);
  // Track embed auth separately since better-auth session store won't update
  let embedAuthenticated = $state(false);

  // Derived: whether user is authenticated (either via cookies or embed token)
  const isAuthenticated = $derived(inIframe ? embedAuthenticated : !!$session.data);

  const origin = $page.url.searchParams.get('origin') || '*';
  const hasEoa = $page.url.searchParams.get('hasEoa') === 'true';

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
    const observer = new ResizeObserver(() => {
      const height = contentEl!.scrollHeight;
      window.parent.postMessage({ type: 'openkey:resize', height }, '*');
    });
    observer.observe(contentEl);
    return () => observer.disconnect();
  });

  // Reactively load keys when session becomes available
  $effect(() => {
    if (isAuthenticated && !keysLoaded) {
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
    const response: Record<string, any> = {
      type: 'openkey:auth:response',
      success: true,
      address: key.address,
      keyId: key.id,
      keyType: key.keyType,
    };
    // Pass session token so SDK can relay it to subsequent iframes
    const token = getSessionToken();
    if (token) response.sessionToken = token;
    sendResponse(response);
  }

  function linkWallet() {
    // In embed mode, delegate wallet linking to parent SDK
    window.parent.postMessage({ type: 'openkey:link-wallet:delegate' }, origin);
  }

  function register() {
    if (inIframe) {
      // Open register page in a popup directly from this click handler.
      // Must be synchronous with the user gesture — if we delegate to the
      // parent SDK via postMessage, the gesture context is lost and mobile
      // browsers silently block the popup.
      const registerUrl = `${window.location.origin}/auth/register?embed=true`;
      const popup = window.open(registerUrl, 'openkey-register', 'popup=true');
      if (!popup) {
        // Popup blocked — fall back to navigating the iframe itself
        window.location.href = '/auth/register?embed=true';
        return;
      }
      // Listen for completion from the popup
      const onMessage = (event: MessageEvent) => {
        if (event.data?.type === 'openkey:register:complete' && event.data.sessionToken) {
          window.removeEventListener('message', onMessage);
          clearInterval(poll);
          popup.close();
          setSessionToken(event.data.sessionToken);
          embedAuthenticated = true;
        }
      };
      window.addEventListener('message', onMessage);
      const poll = setInterval(() => {
        if (popup.closed) {
          window.removeEventListener('message', onMessage);
          clearInterval(poll);
        }
      }, 500);
    } else {
      window.location.href = '/auth/register';
    }
  }

  function cancel() {
    sendResponse({
      type: 'openkey:auth:response',
      success: false,
      error: { code: 'USER_CANCELLED', message: 'User cancelled' },
    });
    sendClose();
  }

  function useExternalWallet() {
    sendResponse({ type: 'openkey:auth:use-external-wallet' });
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

  async function signInWithPasskey() {
    signingIn = true;
    error = '';
    try {
      if (inIframe) {
        await embedSignInPasskey();
        embedAuthenticated = true;
      } else {
        const result = await authClient.signIn.passkey();
        if (result.error) {
          error = result.error.message || 'Passkey sign-in failed';
        }
      }
    } catch (e: any) {
      error = e.message || 'Passkey sign-in failed';
    } finally {
      signingIn = false;
    }
  }
</script>

<div bind:this={contentEl} class="flex flex-col gap-4 bg-[#fafafa] p-4 rounded-2xl">
  <!-- Logo + Header -->
  <div class="flex flex-col items-center gap-3">
    <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-surface-800 to-surface-900 flex items-center justify-center shadow-sm">
      <svg class="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
      </svg>
    </div>
    <h1 class="text-lg font-semibold text-surface-900">Connect to {appName || 'App'}</h1>
  </div>

  <!-- Card body -->
  <div class="bg-white border border-surface-200 rounded-2xl shadow-sm p-5">
    {#if !isAuthenticated}
      <div class="flex flex-col items-center justify-center text-center py-2">
        <p class="text-surface-500 text-sm mb-4">Sign in with your passkey to continue</p>

        {#if error}
          <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
            {error}
          </div>
        {/if}

        <Button onclick={signInWithPasskey} disabled={signingIn} class="w-full rounded-xl">
          {signingIn ? 'Signing in...' : 'Sign in with Passkey'}
        </Button>

        {#if hasEoa}
          <button
            onclick={useExternalWallet}
            class="mt-3 text-xs text-surface-400 hover:text-surface-600 transition-colors bg-transparent border-none cursor-pointer"
          >
            or use an external wallet
          </button>
        {/if}
      </div>
    {:else if loading}
      <div class="flex flex-col items-center justify-center text-center text-surface-400 py-6">
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
      <div class="flex flex-col items-center justify-center text-center py-2">
        <p class="text-surface-500 text-sm mb-4">No keys found. Generate your first key to connect.</p>
        <Button onclick={generateAndSelect} class="w-full rounded-xl">
          Generate Key
        </Button>
      </div>
    {:else}
      <div class="flex flex-col gap-2.5">
        <p class="text-surface-500 text-sm">Select a key to connect:</p>
        {#each keys as key}
          <button
            class="flex justify-between items-center p-3.5 bg-white border border-surface-200 rounded-xl text-surface-900 cursor-pointer transition-all hover:border-surface-900 hover:bg-surface-50"
            class:border-surface-900={selectedKey?.id === key.id}
            class:bg-surface-50={selectedKey?.id === key.id}
            onclick={() => selectKey(key)}
          >
            <span class="font-medium text-sm flex items-center gap-2">
              {key.label || `Key ${key.keyIndex}`}
              {#if key.keyType === 'EXTERNAL'}
                <span class="text-xs font-medium px-1.5 py-0.5 rounded-md bg-surface-100 text-surface-500">(External)</span>
              {/if}
            </span>
            <div class="flex items-center gap-2">
              <code class="font-mono text-surface-400 text-xs">{formatAddress(key.address)}</code>
              {#if selectedKey?.id === key.id}
                <svg class="w-4 h-4 text-surface-900" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              {/if}
            </div>
          </button>
        {/each}
        <Button variant="secondary" size="sm" onclick={generateAndSelect} class="rounded-xl">
          + Generate New Key
        </Button>
        <Button variant="secondary" size="sm" onclick={linkWallet} class="rounded-xl">
          Link External Wallet
        </Button>
      </div>
    {/if}
  </div>

  {#if isAuthenticated}
    <button
      onclick={() => {
        if (inIframe) {
          clearSessionToken();
          embedAuthenticated = false;
          keysLoaded = false;
          keys = [];
        } else {
          authClient.signOut();
        }
      }}
      class="text-xs text-surface-400 hover:text-surface-600 transition-colors bg-transparent border-none cursor-pointer mx-auto block"
    >
      Sign out
    </button>
  {:else}
    <div class="flex items-center justify-center gap-3 text-sm">
      <button onclick={register} class="text-surface-500 hover:text-surface-700 transition-colors bg-transparent border-none cursor-pointer text-sm">Register</button>
      <span class="text-surface-300">|</span>
      <a href="/auth/recover" class="text-surface-500 hover:text-surface-700 transition-colors">Recover account</a>
    </div>
  {/if}

  <!-- Trust badge -->
  <div class="flex items-center justify-center gap-1.5 text-surface-400">
    <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
    <span class="text-xs">Protected by TEE hardware security</span>
  </div>
</div>
