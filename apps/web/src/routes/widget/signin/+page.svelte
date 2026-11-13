<script lang="ts">
  import { listenForSignInCancellation } from '$lib/signin-cancellation';
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { startAuthentication } from '@simplewebauthn/browser';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import EmbeddedSignIn from '$lib/components/auth/embedded-sign-in.svelte';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import { copyText } from '$lib/clipboard';
  import { originAuthority } from '$lib/requester-display';

  const session = authClient.useSession();
  const origin = $page.url.searchParams.get('origin') ?? '';
  const requestId = $page.url.searchParams.get('requestId') ?? '';
  const chainId = Number($page.url.searchParams.get('chainId'));
  const host = originAuthority(origin);
  let keys = $state<EthereumKey[]>([]);
  let keyId = $state('');
  let error = $state('');
  let busy = $state(false);
  let ready = $state(false);
  let copied = $state(false);
  let token = $state('');
  let handingOff = false;
  let pinnedSession: string | undefined;
  const apiUrl = import.meta.env.VITE_API_URL || '';
  const selectedKey = $derived(keys.find(key => key.id === keyId));
  const shortAddress = (address: string) => `${address.slice(0, 6)}…${address.slice(-4)}`;

  function post(type: string, data: Record<string, unknown> = {}) {
    window.opener?.postMessage({ type, requestId, protocolVersion: 1, ...data }, origin);
  }
  function payload() { return { token, requestId, origin, keyId, chainId }; }
  async function request(phase: string, data: Record<string, unknown>) {
    const response = await fetch(`${apiUrl}/api/delegate/signin/${phase}`, {
      method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!response.ok) throw new Error('Sign-in could not continue');
    return response.json();
  }
  function cancel() {
    if (token && !handingOff) navigator.sendBeacon(`${apiUrl}/api/delegate/signin/cancel`,
      new Blob([JSON.stringify(payload())], { type: 'application/json' }));
  }
  async function loadKeys() {
    const id = $session.data?.session.id;
    if (!id) return;
    try {
      const result = await api.listKeys();
      if ($session.data?.session.id !== id) return;
      keys = result.keys.filter((key) => !key.archivedAt);
      if (keys.length === 1) keyId = keys[0]!.id;
      pinnedSession = id;
    } catch (cause) { error = String(cause); }
  }
  $effect(() => {
    if (ready && $session.data?.session.id) void loadKeys();
  });
  async function identify() {
    busy = true;
    error = '';
    try {
      const options = await request('options', payload());
      token = options.token;
      const response = await startAuthentication({ optionsJSON: options.options });
      if ($session.data?.session.id !== pinnedSession) throw new Error('Sign-in account changed');
      const identity = await request('verify', { ...payload(), response });
      post('openkey:signin:identity', { identity });
    } catch (cause) {
      cancel();
      error = cause instanceof Error ? cause.message : String(cause);
      post('openkey:signin:error', { error });
    } finally { busy = false; }
  }
  onMount(() => {
    if (!window.opener || !requestId || !Number.isSafeInteger(chainId) || chainId <= 0 ||
        !origin || new URL(origin).origin !== origin) return;
    void fetch(`${apiUrl}/api/delegate/signin/capabilities`, { credentials: 'omit' })
      .then(response => response.ok ? response.json() : null)
      .then(capability => { ready = capability?.enabled === true && capability?.protocolVersion === 1; })
      .catch(() => { ready = false; });
    const receive = async (event: MessageEvent) => {
      if (event.origin !== origin || event.source !== window.opener ||
          event.data?.requestId !== requestId || event.data?.protocolVersion !== 1) return;
      if (event.data.type === 'openkey:signin:resume' && token &&
          event.data.token === token && $session.data?.session.id === pinnedSession) {
        try {
          const resumed = await request('resume', payload());
          if (resumed.resumed !== true) throw new Error('Sign-in handoff refused');
          handingOff = true;
          post('openkey:signin:resumed');
        } catch {
          cancel();
          post('openkey:signin:error', { error: 'Sign-in could not continue' });
        }
      }
      if (event.data.type === 'openkey:close') { cancel(); window.close(); }
    };
    const stopCancellation = listenForSignInCancellation(() => token ? payload() : undefined, () => { handingOff = false; });
    window.addEventListener('message', receive);
    window.addEventListener('pagehide', cancel);
    return () => { stopCancellation(); window.removeEventListener('message', receive); window.removeEventListener('pagehide', cancel); };
  });
</script>

{#if ready}
  <main class="mx-auto w-full max-w-md p-6">
    <Card class="space-y-6">
      <header class="space-y-2">
        <h1 class="text-2xl font-semibold text-surface-900">Sign in</h1>
        <p class="break-words text-sm text-surface-500">Requested by <strong class="font-semibold text-surface-900">{host}</strong></p>
      </header>
      {#if !$session.data}
        <EmbeddedSignIn prompt="" onauthenticated={loadKeys} />
      {:else}
        <div class="space-y-3">
          {#if keys.length > 1}
            <label for="signin-key" class="block text-sm font-medium text-surface-900">Choose which key signs in:</label>
            <select id="signin-key" class="w-full min-w-0 rounded-xl border border-surface-200 bg-white px-3 py-3 text-surface-900 focus-visible:outline-2 focus-visible:outline-surface-900" bind:value={keyId} disabled={busy || !!token} onchange={() => { copied = false; }}>
              <option value="" disabled>Choose a key</option>
              {#each keys as key}<option value={key.id}>{shortAddress(key.address)}</option>{/each}
            </select>
          {:else if selectedKey}
            <p class="font-medium text-surface-900" title={selectedKey.address}>{shortAddress(selectedKey.address)}</p>
          {/if}
          {#if selectedKey}
            <Button variant="secondary" size="sm" onclick={async () => { const address = selectedKey?.address; if (address) copied = await copyText(address); }}>
              {copied ? 'Copied' : 'Copy full address'}
            </Button>
          {/if}
        </div>
        <div class="space-y-3">
          <p id="signin-disclosure" class="text-sm leading-relaxed text-surface-600">
            {#if keys.length > 1}
              Signing in shares the address of the key you choose with {host}. Next, you'll review what it can do.
            {:else}
              Signing in shares your public address with {host}. Next, you'll review what it can do.
            {/if}
          </p>
          <Button class="w-full" size="lg" aria-describedby="signin-disclosure" onclick={identify} disabled={busy || !keyId || !!token}>Continue with passkey</Button>
        </div>
      {/if}
      {#if error}<p role="alert" class="text-sm text-red-600">{error}</p>{/if}
    </Card>
  </main>
{/if}
