<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { startAuthentication } from '@simplewebauthn/browser';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import EmbeddedSignIn from '$lib/components/auth/embedded-sign-in.svelte';
  import Button from '$lib/components/ui/button.svelte';

  const session = authClient.useSession();
  const origin = $page.url.searchParams.get('origin') ?? '';
  const requestId = $page.url.searchParams.get('requestId') ?? '';
  const chainId = Number($page.url.searchParams.get('chainId'));
  let keys = $state<EthereumKey[]>([]);
  let keyId = $state('');
  let error = $state('');
  let busy = $state(false);
  let ready = $state(false);
  let token = $state('');
  let handingOff = false;
  let pinnedSession: string | undefined;
  const apiUrl = import.meta.env.VITE_API_URL || '';

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
    ready = true;
    const receive = (event: MessageEvent) => {
      if (event.origin !== origin || event.source !== window.opener ||
          event.data?.requestId !== requestId || event.data?.protocolVersion !== 1) return;
      if (event.data.type === 'openkey:signin:resume' && token &&
          event.data.token === token && $session.data?.session.id === pinnedSession) {
        handingOff = true;
        post('openkey:signin:resumed');
      }
      if (event.data.type === 'openkey:close') { cancel(); window.close(); }
    };
    window.addEventListener('message', receive);
    window.addEventListener('pagehide', cancel);
    return () => { window.removeEventListener('message', receive); window.removeEventListener('pagehide', cancel); };
  });
</script>

{#if ready}
  <main class="mx-auto max-w-md p-6">
    {#if !$session.data}
      <EmbeddedSignIn prompt="Sign in" onauthenticated={loadKeys} />
    {:else}
      <!-- TC-2913: placeholder disclosure; Monica owns final wording before review/ship. -->
      <p>Share your wallet address with {origin} to prepare your TinyCloud sign-in.</p>
      <select aria-label="Key" bind:value={keyId} disabled={busy || !!token}>
        <option value="" disabled>Choose a key</option>
        {#each keys as key}<option value={key.id}>{key.address}</option>{/each}
      </select>
      <Button onclick={identify} disabled={busy || !keyId || !!token}>Continue with passkey</Button>
    {/if}
    {#if error}<p role="alert">{error}</p>{/if}
  </main>
{/if}
