<script lang="ts">
  import { getContext } from 'svelte';
  import { page } from '$app/stores';
  import { CONSOLE_SHELL, type ConsoleShellContext } from '$lib/console-shell';
  import { api, type ConsoleWebhookDelivery, type ConsoleWebhookEndpoint } from '$lib/api';
  import { copyText } from '$lib/clipboard';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  const { overview, refresh } = getContext<ConsoleShellContext>(CONSOLE_SHELL);
  let currentOrganizationId = $derived($page.params.organizationId ?? '');

  let endpoints = $state<ConsoleWebhookEndpoint[]>([]);
  let supportedEventTypes = $state<string[]>([]);
  let deliveries = $state<ConsoleWebhookDelivery[]>([]);
  let selectedEndpointId = $state<string | null>(null);
  let loading = $state(true);
  let loadingDeliveries = $state(false);
  let error = $state('');
  let createError = $state('');
  let createLoading = $state(false);
  let deleteLoading = $state('');
  let secretReveal = $state<{ endpoint: ConsoleWebhookEndpoint; secret: string } | null>(null);
  let copyState = $state<'idle' | 'copied' | 'failed'>('idle');
  let acknowledged = $state(false);
  let loadedFor = $state('');

  let url = $state('');
  let selectedEvents = $state<string[]>(['managed_account.created']);

  function selectedEndpoint() {
    return endpoints.find((endpoint) => endpoint.id === selectedEndpointId) ?? endpoints[0] ?? null;
  }

  function toggleEvent(eventType: string) {
    if (selectedEvents.includes(eventType)) {
      selectedEvents = selectedEvents.filter((value) => value !== eventType);
    } else {
      selectedEvents = [...selectedEvents, eventType];
    }
  }

  async function loadEndpoints() {
    loading = true;
    error = '';
    try {
      const result = await api.listConsoleWebhookEndpoints(currentOrganizationId);
      endpoints = result.endpoints;
      supportedEventTypes = result.supportedEventTypes;
      if (!selectedEndpointId || !endpoints.some((endpoint) => endpoint.id === selectedEndpointId)) {
        selectedEndpointId = endpoints[0]?.id ?? null;
      }
      if (selectedEndpointId) {
        await loadDeliveries(selectedEndpointId);
      } else {
        deliveries = [];
      }
    } catch (caught: any) {
      error = caught.message || 'Could not load webhooks.';
    } finally {
      loading = false;
    }
  }

  async function loadDeliveries(endpointId: string) {
    if (!endpointId) {
      deliveries = [];
      return;
    }
    loadingDeliveries = true;
    try {
      const result = await api.listConsoleWebhookDeliveries(currentOrganizationId, endpointId, { limit: 20 });
      deliveries = result.deliveries;
    } catch (caught: any) {
      error = caught.message || 'Could not load delivery history.';
    } finally {
      loadingDeliveries = false;
    }
  }

  async function createEndpoint() {
    createLoading = true;
    createError = '';
    if (!url.trim()) {
      createError = 'Enter a webhook URL.';
      createLoading = false;
      return;
    }
    if (selectedEvents.length === 0) {
      createError = 'Select at least one event.';
      createLoading = false;
      return;
    }
    try {
      const result = await api.createConsoleWebhookEndpoint(currentOrganizationId, {
        url: url.trim(),
        eventTypes: selectedEvents,
      });
      secretReveal = { endpoint: result.endpoint, secret: result.secret };
      acknowledged = false;
      copyState = 'idle';
      url = '';
      selectedEvents = ['managed_account.created'];
      await Promise.all([loadEndpoints(), refresh()]);
      selectedEndpointId = result.endpoint.id;
      await loadDeliveries(result.endpoint.id);
    } catch (caught: any) {
      createError = caught.message || 'Could not create the webhook endpoint.';
    } finally {
      createLoading = false;
    }
  }

  async function deleteEndpoint(endpoint: ConsoleWebhookEndpoint) {
    if (!confirm(`Delete ${endpoint.url}? This disables delivery for the selected endpoint.`)) return;
    deleteLoading = endpoint.id;
    error = '';
    try {
      await api.deleteConsoleWebhookEndpoint(currentOrganizationId, endpoint.id);
      await Promise.all([loadEndpoints(), refresh()]);
    } catch (caught: any) {
      error = caught.message || 'Could not delete the webhook endpoint.';
    } finally {
      deleteLoading = '';
    }
  }

  async function copySecret() {
    if (!secretReveal) return;
    copyState = (await copyText(secretReveal.secret)) ? 'copied' : 'failed';
  }

  function eventChipClass(eventType: string) {
    return eventType.includes('failed') || eventType.includes('revoked') ? 'border-amber-200 bg-amber-50 text-amber-700' : 'border-surface-200 bg-surface-50 text-surface-600';
  }

  function deliveryChipClass(status: ConsoleWebhookDelivery['status']) {
    if (status === 'DELIVERED') return 'border-emerald-200 bg-emerald-50 text-emerald-700';
    if (status === 'FAILED') return 'border-red-200 bg-red-50 text-red-700';
    return 'border-amber-200 bg-amber-50 text-amber-700';
  }

  $effect(() => {
    const orgId = currentOrganizationId;
    if (loadedFor !== orgId) {
      loadedFor = orgId;
      selectedEndpointId = null;
      deliveries = [];
      void loadEndpoints();
    }
  });
</script>

<svelte:head>
  <title>Webhooks · OpenKey Console</title>
</svelte:head>

<div class="space-y-6">
  <Card class="space-y-4">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">Webhooks</p>
        <h1 class="mt-2 text-3xl font-semibold tracking-[-0.04em] text-surface-900">Delivery history and endpoint safety</h1>
        <p class="mt-3 max-w-2xl text-sm leading-6 text-surface-600">
          Webhook endpoints accept public HTTPS URLs only. Delivery history is scoped to the selected endpoint, and the secret is shown exactly once on create.
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <span class="rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-semibold text-surface-600">
          { endpoints.length } endpoints
        </span>
        <span class="rounded-full border border-primary-200 bg-primary-50 px-3 py-1 text-xs font-semibold text-primary-700">
          { $overview?.organization.role ?? 'MEMBER' }
        </span>
      </div>
    </div>
    <div class="rounded-2xl border border-dotted border-surface-200 bg-white px-4 py-3 text-sm leading-6 text-surface-600">
      Safe targets are public, non-credentialed HTTPS URLs. Localhost and private-network addresses are rejected by the API.
    </div>
  </Card>

  {#if error}
    <Card class="border-red-200 bg-red-50/60">
      <p class="text-sm font-medium text-red-700">{error}</p>
    </Card>
  {/if}

  {#if secretReveal}
    <Card class="space-y-4 border-primary-200 bg-primary-50/60">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-700">One-time webhook secret</p>
          <h2 class="mt-2 text-lg font-semibold tracking-[-0.03em] text-surface-900">{secretReveal.endpoint.url}</h2>
          <p class="mt-1 text-sm leading-6 text-surface-600">
            Copy this secret now. It will not be retrievable again from the console or the list API.
          </p>
        </div>
        <span class="rounded-full border border-primary-200 bg-white px-3 py-1 text-xs font-semibold text-primary-700">Webhook secret</span>
      </div>
      <div class="rounded-2xl border border-dotted border-surface-200 bg-white p-4">
        <div class="flex items-center justify-between gap-3">
          <code class="break-all font-mono text-sm text-surface-900">{secretReveal.secret}</code>
          <Button variant="secondary" type="button" onclick={() => void copySecret()}>
            {copyState === 'copied' ? 'Copied' : 'Copy'}
          </Button>
        </div>
      </div>
      <div class="rounded-2xl border border-surface-200 bg-white p-4 text-sm leading-6 text-surface-600">
        <strong class="text-surface-900">Warning:</strong> the secret is shown only once and is not stored in browser storage.
      </div>
      <div class="flex flex-wrap gap-2">
        <Button
          type="button"
          disabled={acknowledged}
          onclick={() => {
            acknowledged = true;
            secretReveal = null;
          }}
        >
          {acknowledged ? 'Acknowledged' : 'I saved this secret'}
        </Button>
        <Button variant="secondary" type="button" onclick={() => { secretReveal = null; }}>
          Dismiss
        </Button>
      </div>
    </Card>
  {/if}

  {#if $overview?.organization.role === 'ADMIN'}
    <Card class="space-y-5">
      <div class="flex items-start justify-between gap-4">
        <div>
          <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Create endpoint</h2>
          <p class="mt-1 text-sm leading-6 text-surface-600">
            Use a public HTTPS URL and choose the lifecycle events you need. The endpoint secret appears only after creation.
          </p>
        </div>
        <span class="rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-semibold text-surface-600">Admin only</span>
      </div>

      <form class="space-y-4" onsubmit={(event) => { event.preventDefault(); void createEndpoint(); }}>
        <div class="grid gap-4 lg:grid-cols-2">
          <div class="space-y-2 lg:col-span-2">
            <label class="text-sm font-semibold text-surface-900" for="webhook-url">Webhook URL</label>
            <Input id="webhook-url" bind:value={url} placeholder="https://hooks.example.com/openkey" required />
            <p class="text-xs leading-5 text-surface-500">
              No credentials, no fragments, no localhost, and no private-network targets.
            </p>
          </div>
          <div class="lg:col-span-2 space-y-2">
            <div class="flex items-center justify-between gap-3">
              <span class="text-sm font-semibold text-surface-900">Events</span>
              <span class="text-xs text-surface-500">{selectedEvents.length} selected</span>
            </div>
            <div class="grid gap-2 md:grid-cols-2">
              {#each supportedEventTypes as eventType}
                <label class={`flex items-center justify-between rounded-2xl border px-3 py-2 text-sm ${selectedEvents.includes(eventType) ? 'border-primary-200 bg-primary-50 text-primary-700' : 'border-surface-200 bg-white text-surface-700'}`}>
                  <span class="font-mono text-xs">{eventType}</span>
                  <input type="checkbox" class="h-4 w-4 rounded border-surface-300 text-primary-600 focus-visible:ring-primary-200" checked={selectedEvents.includes(eventType)} onclick={() => toggleEvent(eventType)} />
                </label>
              {/each}
            </div>
          </div>
        </div>

        <div class="flex flex-wrap gap-2">
          <Button type="submit" disabled={createLoading}>{createLoading ? 'Creating...' : 'Create endpoint'}</Button>
          <Button type="button" variant="secondary" onclick={() => { url = ''; selectedEvents = ['managed_account.created']; createError = ''; }}>
            Reset
          </Button>
        </div>
        {#if createError}
          <div class="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{createError}</div>
        {/if}
      </form>
    </Card>
  {:else}
    <Card class="border-surface-200 bg-surface-50">
      <p class="text-sm leading-6 text-surface-600">
        Webhook endpoints are visible to members, but creation and deletion stay hidden because this session is not an administrator.
      </p>
    </Card>
  {/if}

  <div class="grid gap-6 xl:grid-cols-[1fr_0.9fr]">
    <Card class="space-y-4">
      <div class="flex items-center justify-between gap-3">
        <div>
          <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Endpoints</h2>
          <p class="mt-1 text-sm leading-6 text-surface-600">Select an endpoint to inspect its delivery history.</p>
        </div>
        <Button variant="secondary" onclick={() => void loadEndpoints()}>Reload</Button>
      </div>

      {#if loading}
        <div class="space-y-3" aria-label="Loading webhook endpoints">
          <div class="h-24 rounded-2xl bg-surface-100"></div>
          <div class="h-24 rounded-2xl bg-surface-100"></div>
        </div>
      {:else if endpoints.length === 0}
        <div class="rounded-2xl border border-dotted border-surface-200 bg-surface-50 p-6">
          <h3 class="text-base font-semibold text-surface-900">No webhook endpoints yet</h3>
          <p class="mt-2 max-w-2xl text-sm leading-6 text-surface-600">
            Create an endpoint if your integration needs delivery history or event replay visibility. Otherwise you can keep the surface empty.
          </p>
        </div>
      {:else}
        <div class="space-y-3">
          {#each endpoints as endpoint}
            <div class={`flex w-full items-stretch overflow-hidden rounded-2xl border transition-colors ${selectedEndpointId === endpoint.id ? 'border-primary-200 bg-primary-50/60' : 'border-surface-200 bg-white hover:border-surface-300 hover:bg-surface-50'}`}>
              <button
                type="button"
                class="min-w-0 flex-1 p-4 text-left"
                aria-pressed={selectedEndpointId === endpoint.id}
                onclick={() => {
                  selectedEndpointId = endpoint.id;
                  void loadDeliveries(endpoint.id);
                }}
              >
                <span class="flex flex-wrap items-start justify-between gap-3">
                  <span class="min-w-0">
                    <span class="block break-all text-base font-semibold text-surface-900">{endpoint.url}</span>
                    <span class="mt-2 flex flex-wrap gap-2">
                      {#each endpoint.eventTypes as eventType}
                        <span class={`rounded-full border px-2.5 py-1 text-xs font-semibold ${eventChipClass(eventType)}`}>{eventType}</span>
                      {/each}
                    </span>
                  </span>
                  <span class="rounded-full border border-surface-200 bg-surface-50 px-2.5 py-1 text-xs font-semibold text-surface-600">
                    {endpoint.active ? 'Active' : 'Inactive'}
                  </span>
                </span>
              </button>
              {#if $overview?.organization.role === 'ADMIN' && endpoint.active}
                <div class="flex shrink-0 items-center pr-4">
                  <Button
                    variant="secondary"
                    type="button"
                    aria-label={`Delete webhook endpoint ${endpoint.url}`}
                    onclick={() => void deleteEndpoint(endpoint)}
                    disabled={deleteLoading === endpoint.id}
                  >
                    {deleteLoading === endpoint.id ? 'Deleting...' : 'Delete'}
                  </Button>
                </div>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    </Card>

    <Card class="space-y-4">
      {#if selectedEndpoint()}
        {@const endpoint = selectedEndpoint()}
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">Selected endpoint</p>
            <h2 class="mt-2 text-xl font-semibold tracking-[-0.03em] text-surface-900">{endpoint.url}</h2>
            <p class="mt-2 text-sm leading-6 text-surface-600">
              Delivery history is keyed to this endpoint only.
            </p>
          </div>
          <span class={`rounded-full border px-3 py-1 text-xs font-semibold ${endpoint.active ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-surface-200 bg-surface-50 text-surface-600'}`}>
            {endpoint.active ? 'Active' : 'Inactive'}
          </span>
        </div>

        <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
          <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Created</div>
          <div class="mt-2 text-sm font-semibold text-surface-900">{new Date(endpoint.createdAt).toLocaleString()}</div>
          <div class="mt-1 text-xs text-surface-500">Updated {new Date(endpoint.updatedAt).toLocaleString()}</div>
        </div>

        <div class="space-y-3">
          <div class="flex items-center justify-between gap-3">
            <h3 class="text-base font-semibold text-surface-900">Delivery history</h3>
            <Button variant="secondary" onclick={() => void loadDeliveries(endpoint.id)}>{loadingDeliveries ? 'Loading...' : 'Refresh'}</Button>
          </div>
          {#if loadingDeliveries}
            <div class="space-y-3">
              <div class="h-20 rounded-2xl bg-surface-100"></div>
              <div class="h-20 rounded-2xl bg-surface-100"></div>
            </div>
          {:else if deliveries.length === 0}
            <div class="rounded-2xl border border-dotted border-surface-200 bg-white p-4 text-sm leading-6 text-surface-600">
              No deliveries have been recorded for this endpoint yet.
            </div>
          {:else}
            <div class="space-y-3">
              {#each deliveries as delivery}
                <article class="rounded-2xl border border-surface-200 bg-white p-4">
                  <div class="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div class="flex flex-wrap items-center gap-2">
                        <h4 class="font-semibold text-surface-900">{delivery.eventType}</h4>
                        <span class={`rounded-full border px-2.5 py-1 text-xs font-semibold ${deliveryChipClass(delivery.status)}`}>{delivery.status}</span>
                      </div>
                      <p class="mt-2 text-sm leading-6 text-surface-600">Managed account {delivery.managedAccountId}</p>
                    </div>
                    <div class="text-right text-xs text-surface-500">
                      <div>Attempts {delivery.attempts}</div>
                      <div class="mt-1">Epoch {delivery.custodyEpoch}</div>
                    </div>
                  </div>
                  <div class="mt-3 grid gap-2 text-xs text-surface-500 sm:grid-cols-2">
                    <div class="rounded-2xl border border-surface-200 bg-surface-50 p-3">
                      Last attempt: {delivery.lastAttemptAt ? new Date(delivery.lastAttemptAt).toLocaleString() : 'Never'}
                    </div>
                    <div class="rounded-2xl border border-surface-200 bg-surface-50 p-3">
                      Delivered: {delivery.deliveredAt ? new Date(delivery.deliveredAt).toLocaleString() : 'Pending'}
                    </div>
                  </div>
                </article>
              {/each}
            </div>
          {/if}
        </div>
      {:else}
        <div class="rounded-2xl border border-dotted border-surface-200 bg-surface-50 p-6 text-sm leading-6 text-surface-600">
          Select an endpoint to inspect delivery history.
        </div>
      {/if}
    </Card>
  </div>
</div>
