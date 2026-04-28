<script lang="ts">
  import { page } from '$app/stores';
  import { authClient, authErrorMessage } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { isEmbedContext, embedSignInPasskey, setSessionToken } from '$lib/embed-passkey';
  import { parseSIWE } from '$lib/siwe-parser';
  import Button from '$lib/components/ui/button.svelte';
  import SiweMessage from '$lib/components/ui/siwe-message.svelte';

  const session = authClient.useSession();
  const inIframe = typeof window !== 'undefined' && isEmbedContext();

  let message = $state('');
  let keyId = $state<string | null>(null);
  let key = $state<EthereumKey | null>(null);
  let loading = $state(true);
  let signing = $state(false);
  let error = $state('');
  let sessionChecked = $state(false);
  let initialized = $state(false);
  let keyFetched = $state(false);
  let contentEl = $state<HTMLDivElement | undefined>(undefined);
  let signingIn = $state(false);
  let embedAuthenticated = $state(false);

  const isAuthenticated = $derived(inIframe ? embedAuthenticated : !!$session.data);

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
    const observer = new ResizeObserver(() => {
      const height = contentEl!.scrollHeight;
      window.parent.postMessage({ type: 'openkey:resize', height }, '*');
    });
    observer.observe(contentEl);
    return () => observer.disconnect();
  });

  // Reactively update loading state when session becomes available
  $effect(() => {
    if (isAuthenticated && !sessionChecked) {
      sessionChecked = true;
      loading = false;
    }
  });

  // Reactively fetch key when session becomes available and we have a keyId
  $effect(() => {
    if (isAuthenticated && keyId && !keyFetched && !key) {
      keyFetched = true;
      api.getKey(keyId).then(result => {
        key = result.key;
      }).catch(() => {
        // Key not found
      });
    }
  });

  async function handleMessage(event: MessageEvent) {
    if (event.data?.type === 'openkey:sign:request') {
      message = event.data.message;
      keyId = event.data.keyId || null;
      keyFetched = false;

      // Receive session token from SDK (relayed from connect flow)
      if (event.data.sessionToken && inIframe) {
        setSessionToken(event.data.sessionToken);
        embedAuthenticated = true;
      }

      if (keyId && isAuthenticated) {
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

  async function signMessage() {
    if (!key || !message) return;

    signing = true;
    error = '';

    try {
      const result = await api.signMessage(key.id, message);
      sendResponse({
        type: 'openkey:sign:response',
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
      type: 'openkey:sign:response',
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

  let siweDomain = $derived(message ? parseSIWE(message)?.message.domain ?? null : null);

  let originDomain = $derived.by(() => {
    if (!origin || origin === '*') return null;
    try { return new URL(origin).hostname; } catch { return origin; }
  });

  let domainMismatch = $derived(
    siweDomain && originDomain && siweDomain !== originDomain
  );

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
          error = authErrorMessage(result.error, 'Passkey sign-in failed');
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
  <!-- Header -->
  <div class="flex flex-col items-center gap-3">
    <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-surface-800 to-surface-900 flex items-center justify-center shadow-sm">
      <svg class="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
      </svg>
    </div>
    <h1 class="text-lg font-semibold text-surface-900">Sign Message</h1>
  </div>

  <!-- Card body -->
  <div class="bg-white border border-surface-200 rounded-2xl shadow-sm p-5">
    {#if !isAuthenticated}
      <div class="flex flex-col items-center justify-center text-center py-2">
        <p class="text-surface-500 text-sm mb-4">Sign in with your passkey to sign messages</p>

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
      <div class="flex flex-col items-center justify-center text-center text-surface-400 py-6">
        <svg class="w-6 h-6 animate-spin text-surface-400 mb-3" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
        </svg>
        <span class="text-sm text-surface-500">Loading...</span>
      </div>
    {:else if !key}
      <div class="flex flex-col items-center justify-center text-center text-surface-500 py-4">
        <p class="text-sm">Please connect first to sign messages.</p>
      </div>
    {:else}
      <div class="flex flex-col gap-3">
        <!-- Signing with -->
        <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
          <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Signing with</span>
          <div class="flex items-center gap-2">
            <span class="font-medium text-sm text-surface-900">{key.label || `Key ${key.keyIndex}`}</span>
            <code class="font-mono text-surface-400 text-xs">{formatAddress(key.address)}</code>
          </div>
        </div>

        <!-- Request from -->
        {#if siweDomain}
          <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
            <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Request from</span>
            <span class="text-sm font-medium text-surface-900">{siweDomain}</span>
            {#if domainMismatch}
              <div class="mt-1.5 text-xs text-amber-600">
                Domain mismatch: requesting page is {originDomain} but message is from {siweDomain}
              </div>
            {/if}
          </div>
        {/if}

        <!-- Message -->
        <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
          <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Message</span>
          <SiweMessage {message} theme="light" />
        </div>

        {#if error}
          <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex gap-2 mt-1">
          <Button variant="secondary" size="sm" class="flex-1 rounded-xl" onclick={cancel}>Cancel</Button>
          <Button size="sm" class="flex-1 rounded-xl" onclick={signMessage} disabled={signing}>
            {signing ? 'Signing...' : 'Sign Message'}
          </Button>
        </div>
      </div>
    {/if}
  </div>

  <!-- Trust badge -->
  <div class="flex items-center justify-center gap-1.5 text-surface-400">
    <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
    <span class="text-xs">Protected by TEE hardware security</span>
  </div>
</div>
