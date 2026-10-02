<script lang="ts">
  import { page } from '$app/stores';
  import { API_BASE } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import {
    deviceLifetimeOptions,
    deviceRequestReason,
    deviceRequestTtlSeconds,
    encodeBase64UrlJson,
    isShareOnlyDeviceRequest,
    lookupDeviceRequest,
    type DeviceRequestRecord,
  } from '$lib/device-authorization';

  let userCode = $state($page.url.searchParams.get('user_code') ?? '');
  let request = $state<DeviceRequestRecord | null>(null);
  let loading = $state(false);
  let error = $state('');
  /** The CLI's requested lifetime, fixed when the request is looked up. */
  let maxLifetimeSeconds = $state(0);
  let lifetimeSeconds = $state(0);
  const lifetimeOptions = $derived(deviceLifetimeOptions(maxLifetimeSeconds));
  const requestReason = $derived(request ? deviceRequestReason(request) : '');
  const SERVICE_LABELS: Record<string, string> = {
    'tinycloud.kv': 'Key-value storage',
    'tinycloud.capabilities': 'Capability list',
  };

  function normalizedCode(value: string): string {
    return value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
  }

  function displayedCode(value: string): string {
    const normalized = normalizedCode(value);
    return normalized.length > 4 ? `${normalized.slice(0, 4)}-${normalized.slice(4)}` : normalized;
  }

  const delegateHref = $derived.by(() => {
    if (!request) return '';
    // The delegation may last at most the CLI's requested lifetime.
    const selectedSeconds = Math.min(lifetimeSeconds, maxLifetimeSeconds);
    const params = new URLSearchParams({
      did: request.sessionDid,
      jwk: encodeBase64UrlJson(request.publicJwk),
      relayJwk: encodeBase64UrlJson(request.relayPublicJwk),
      host: request.nodeOrigin,
      permissions: encodeBase64UrlJson({
        permissions: request.permissions,
        ...(requestReason ? { reason: requestReason } : {}),
      }),
      ...(requestReason ? { reason: requestReason } : {}),
      expiry: `${selectedSeconds}s`,
      protocolVersion: '1',
      deviceTransactionId: request.id,
      deviceShareOrigin: request.shareOrigin,
      // /delegate re-reads the request by code and refuses a mismatched link.
      deviceUserCode: displayedCode(request.userCode),
    });
    return `/delegate?${params.toString()}`;
  });

  async function findRequest() {
    loading = true;
    error = '';
    request = null;
    try {
      const found = await lookupDeviceRequest(API_BASE, displayedCode(userCode));
      if (!found) throw new Error('That code is invalid or expired. Restart the CLI command and try again.');
      maxLifetimeSeconds = deviceRequestTtlSeconds(found);
      lifetimeSeconds = maxLifetimeSeconds;
      request = found;
      userCode = displayedCode(found.userCode);
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
  <title>Approve TinyCloud CLI — OpenKey</title>
</svelte:head>

<main class="mx-auto flex min-h-screen max-w-2xl items-center px-4 py-12">
  <Card class="w-full p-6 sm:p-8">
    <p class="mb-2 text-sm font-medium text-primary-600">TinyCloud CLI</p>
    <h1 class="mb-3 text-2xl font-semibold text-surface-900">{request && isShareOnlyDeviceRequest(request) ? 'Approve a Share publishing session' : 'Approve TinyCloud CLI access'}</h1>
    <p class="mb-6 text-surface-600">Enter the code shown in your terminal. OpenKey lists every capability the CLI asks for; after you sign in you can uncheck optional ones, confirm the request is yours, and approve.</p>

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
      <section class="mt-8 flex flex-col gap-5 border-t border-surface-200 pt-6">
        <div class="rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900" role="note">
          <p class="font-semibold">Only approve if you started this on your own device.</p>
          <p class="mt-1">Approving hands this access to the terminal that showed you the code. If someone else sent you this code or link, stop here.</p>
        </div>

        <div>
          <h2 class="text-sm text-surface-500">Reason given by the CLI</h2>
          <p class="mt-1 text-sm text-surface-900">{requestReason || 'No reason was provided.'}</p>
        </div>

        <div>
          <h2 class="text-sm text-surface-500">Requested capabilities ({request.permissions.length})</h2>
          <ul class="mt-2 divide-y divide-surface-200 rounded-lg border border-surface-200">
            {#each request.permissions as permission (`${permission.service}\0${permission.path}`)}
              <li class="px-3 py-2 text-sm">
                <div class="flex flex-wrap items-baseline justify-between gap-2">
                  <span class="font-medium text-surface-900">
                    {Object.hasOwn(SERVICE_LABELS, permission.service) ? SERVICE_LABELS[permission.service] : permission.service}
                    {#if permission.service === 'tinycloud.capabilities'}
                      <span class="ml-1 rounded bg-surface-100 px-1.5 py-0.5 text-xs font-medium text-surface-600">required</span>
                    {/if}
                  </span>
                  <span class="break-all font-mono text-xs text-surface-700">{permission.path || 'entire space'}</span>
                </div>
                <p class="mt-0.5 text-xs text-surface-500">
                  {permission.actions.map((action) => action.slice(action.indexOf('/') + 1)).join(', ')}
                  · space <span class="break-all font-mono">{permission.space}</span>
                </p>
              </li>
            {/each}
          </ul>
        </div>

        <dl class="grid gap-4 text-sm sm:grid-cols-2">
          <div>
            <dt><label class="text-surface-500" for="delegation-lifetime">Delegation lifetime</label></dt>
            <dd class="mt-1">
              <select id="delegation-lifetime" bind:value={lifetimeSeconds} class="rounded-md border border-surface-300 bg-white px-2 py-1 font-medium text-surface-900">
                {#each lifetimeOptions as option (option.seconds)}
                  <option value={option.seconds}>{option.label}</option>
                {/each}
              </select>
            </dd>
          </div>
          <div><dt class="text-surface-500">Share origin</dt><dd class="break-all font-mono text-xs text-surface-900">{request.shareOrigin}</dd></div>
          <div><dt class="text-surface-500">Node origin</dt><dd class="break-all font-mono text-xs text-surface-900">{request.nodeOrigin}</dd></div>
        </dl>
        <p class="text-sm text-surface-600">The CLI private key never leaves its device. Approval returns one delegation bound to its public session key, these origins, and exactly the capabilities you approve. Reading the space's capability list is required for every delegation.</p>
        <Button href={delegateHref} class="w-full">Sign in and review delegation</Button>
      </section>
    {/if}
  </Card>
</main>
