<script lang="ts">
  import { page } from '$app/stores';
  import { API_BASE } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  type DeviceRequest = {
    id: string;
    userCode: string;
    sessionDid: string;
    publicJwk: Record<string, unknown>;
    relayPublicJwk: Record<string, unknown>;
    permissions: Array<{ service: string; space: string; path: string; actions: string[] }>;
    nodeOrigin: string;
    shareOrigin: string;
    delegationExpiresAt: string;
    transactionExpiresAt: string;
    descriptorDigest: string;
    descriptor: {
      version: 1;
      requester: { id: string; displayLabel: string };
      templateId: string;
      policyId: string;
      capabilities: Array<{ service: string; space: string; path: string; actions: string[] }>;
      resources: { nodeOrigin: string; shareOrigin: string };
      reason: string;
      expiryPolicy: { adjustment: 'narrow-only'; minimumSeconds: number; defaultSeconds: number; maximumSeconds: number };
    };
  };

  let userCode = $state($page.url.searchParams.get('user_code') ?? '');
  let request = $state<DeviceRequest | null>(null);
  let loading = $state(false);
  let error = $state('');
  let delegationDays = $state('30');

  function normalizedCode(value: string): string {
    return value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
  }

  function displayedCode(value: string): string {
    const normalized = normalizedCode(value);
    return normalized.length > 4 ? `${normalized.slice(0, 4)}-${normalized.slice(4)}` : normalized;
  }

  function base64Url(value: unknown): string {
    const bytes = new TextEncoder().encode(JSON.stringify(value));
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  const delegateHref = $derived.by(() => {
    if (!request) return '';
    const remainingSeconds = Math.max(request.descriptor.expiryPolicy.minimumSeconds, Math.floor((Date.parse(request.delegationExpiresAt) - Date.now()) / 1000));
    const selectedSeconds = Number(delegationDays) * 24 * 60 * 60;
    const params = new URLSearchParams({
      did: request.sessionDid,
      jwk: base64Url(request.publicJwk),
      relayJwk: base64Url(request.relayPublicJwk),
      host: request.descriptor.resources.nodeOrigin,
      permissions: base64Url({
        permissions: request.descriptor.capabilities,
        reason: request.descriptor.reason,
      }),
      reason: request.descriptor.reason,
      expiry: `${Math.min(remainingSeconds, request.descriptor.expiryPolicy.maximumSeconds, selectedSeconds)}s`,
      protocolVersion: `${request.descriptor.version}`,
      deviceTransactionId: request.id,
      deviceShareOrigin: request.descriptor.resources.shareOrigin,
      deviceDescriptorDigest: request.descriptorDigest,
    });
    return `/delegate?${params.toString()}`;
  });

  async function findRequest() {
    loading = true;
    error = '';
    request = null;
    try {
      const response = await fetch(`${API_BASE}/api/device-authorizations/lookup?user_code=${encodeURIComponent(displayedCode(userCode))}`, {
        credentials: 'omit',
        headers: { accept: 'application/json' },
      });
      if (!response.ok) throw new Error('That code is invalid or expired. Restart the CLI command and try again.');
      request = await response.json();
      userCode = displayedCode(request!.userCode);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Could not load the device request.';
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    if (userCode && !request && !loading && !error) void findRequest();
  });
</script>

<svelte:head>
  <title>Approve device authorization — OpenKey</title>
</svelte:head>

<main class="mx-auto flex min-h-screen max-w-2xl items-center px-4 py-12">
  <Card class="w-full p-6 sm:p-8">
    <p class="mb-2 text-sm font-medium text-primary-600">Device authorization</p>
    <h1 class="mb-3 text-2xl font-semibold text-surface-900">Approve a session</h1>
    <p class="mb-6 text-surface-600">Enter the code shown in your terminal. OpenKey will ask you to sign in and review the server-authorized request.</p>

    <form class="flex flex-col gap-3 sm:flex-row" onsubmit={(event) => { event.preventDefault(); void findRequest(); }}>
      <input
        class="min-w-0 flex-1 rounded-lg border border-surface-300 bg-white px-4 py-3 font-mono text-lg uppercase tracking-widest text-surface-900"
        aria-label="Device code"
        autocomplete="one-time-code"
        placeholder="ABCD-EFGH"
        value={displayedCode(userCode)}
        oninput={(event) => { userCode = displayedCode(event.currentTarget.value); error = ''; request = null; }}
      />
      <Button type="submit" disabled={loading || normalizedCode(userCode).length !== 8}>
        {loading ? 'Checking…' : 'Continue'}
      </Button>
    </form>

    {#if error}
      <p class="mt-4 rounded-lg bg-red-50 p-3 text-sm text-red-700" role="alert">{error}</p>
    {/if}

    {#if request}
      <section class="mt-8 border-t border-surface-200 pt-6">
        <dl class="grid gap-4 text-sm sm:grid-cols-2">
          <div><dt class="text-surface-500">Requester</dt><dd class="font-medium text-surface-900">{request.descriptor.requester.displayLabel}</dd></div>
          <div><dt class="text-surface-500">Policy</dt><dd class="font-mono text-xs text-surface-900">{request.descriptor.policyId}</dd></div>
          <div>
            <dt><label class="text-surface-500" for="delegation-lifetime">Delegation lifetime</label></dt>
            <dd class="mt-1">
              <select id="delegation-lifetime" bind:value={delegationDays} class="rounded-md border border-surface-300 bg-white px-2 py-1 font-medium text-surface-900">
                {#if request.descriptor.expiryPolicy.maximumSeconds >= 86400}<option value="1">1 day</option>{/if}
                {#if request.descriptor.expiryPolicy.maximumSeconds >= 604800}<option value="7">7 days</option>{/if}
                {#if request.descriptor.expiryPolicy.maximumSeconds >= 2592000}<option value="30">30 days (default)</option>{/if}
              </select>
            </dd>
          </div>
          <div><dt class="text-surface-500">Capabilities</dt><dd class="break-all font-mono text-xs text-surface-900">{request.descriptor.capabilities.map((capability) => capability.actions.join(', ')).join(', ')}</dd></div>
          <div><dt class="text-surface-500">Share origin</dt><dd class="break-all font-mono text-xs text-surface-900">{request.descriptor.resources.shareOrigin}</dd></div>
          <div><dt class="text-surface-500">Node origin</dt><dd class="break-all font-mono text-xs text-surface-900">{request.descriptor.resources.nodeOrigin}</dd></div>
        </dl>
        <p class="my-5 text-sm text-surface-600">{request.descriptor.reason}</p>
        <Button href={delegateHref} class="w-full">Sign in and review delegation</Button>
      </section>
    {/if}
  </Card>
</main>
