<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import { api, type OrganizationSummary } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Input from '$lib/components/ui/input.svelte';

  const session = authClient.useSession();
  let organizations = $state<OrganizationSummary[]>([]);
  let loading = $state(true);
  let error = $state('');
  let showCreate = $state(false);
  let name = $state('');
  let brokerDid = $state('');
  let creating = $state(false);
  let loaded = false;

  const planDescriptions = {
    FREE: 'Embedded registration and eject with starter limits.',
    PRO: 'Higher account, app, request, and retention limits with lifecycle webhooks.',
    ENTERPRISE: 'Contracted limits, controls, compliance, and dedicated infrastructure options.',
  } as const;

  $effect(() => {
    if (!$session.isPending && !$session.data) goto('/auth/login');
    if (!$session.isPending && $session.data && !loaded) { loaded = true; load(); }
  });

  async function load() {
    loading = true;
    try { organizations = (await api.listOrganizations()).organizations; }
    catch (e: any) { error = e.message || 'Could not load organizations.'; }
    finally { loading = false; }
  }

  async function createOrganization() {
    creating = true;
    error = '';
    try {
      await api.createOrganization(name, brokerDid);
      name = '';
      brokerDid = '';
      showCreate = false;
      await load();
    } catch (e: any) {
      error = e.message || 'Could not create the organization.';
    } finally {
      creating = false;
    }
  }
</script>

<svelte:head><title>Organizations · OpenKey</title></svelte:head>

<div class="mx-auto max-w-5xl px-4 py-10">
  <div class="mb-8 flex flex-wrap items-end justify-between gap-4">
    <div>
      <h1 class="text-2xl font-semibold text-surface-900">Organizations</h1>
      <p class="mt-2 max-w-2xl text-sm leading-6 text-surface-600">Tenant boundaries for apps, server credentials, managed accounts, and plan usage.</p>
    </div>
    <Button onclick={() => showCreate = !showCreate}>{showCreate ? 'Cancel' : 'New organization'}</Button>
  </div>

  {#if error}<div class="mb-5 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" role="alert">{error}</div>{/if}

  {#if showCreate}
    <form onsubmit={(event) => { event.preventDefault(); createOrganization(); }} class="mb-7 rounded-2xl bg-white p-6 shadow-sm">
      <h2 class="text-lg font-semibold text-surface-900">Create a Free organization</h2>
      <p class="mt-1 text-sm text-surface-600">Every new organization starts on Free. The broker DID receives each account’s bounded tenant-parent delegation.</p>
      <div class="mt-5 grid gap-4 sm:grid-cols-2">
        <div><label for="organization-name" class="mb-1.5 block text-sm font-medium text-surface-800">Organization name</label><Input id="organization-name" bind:value={name} required /></div>
        <div><label for="broker-did" class="mb-1.5 block text-sm font-medium text-surface-800">Broker DID</label><Input id="broker-did" bind:value={brokerDid} placeholder="did:key:z…" required /></div>
      </div>
      <Button type="submit" class="mt-5" disabled={creating}>{creating ? 'Creating…' : 'Create organization'}</Button>
    </form>
  {/if}

  {#if loading}
    <div class="h-32 animate-pulse rounded-xl bg-surface-100" aria-label="Loading organizations"></div>
  {:else if organizations.length === 0}
    <div class="rounded-2xl bg-white p-8 shadow-sm"><h2 class="font-semibold text-surface-900">No organizations yet</h2><p class="mt-2 text-sm text-surface-600">Create one to register tenant apps and managed accounts.</p></div>
  {:else}
    <div class="space-y-5">
      {#each organizations as organization}
        <section class="rounded-2xl bg-white p-6 shadow-sm">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div><h2 class="text-lg font-semibold text-surface-900">{organization.name}</h2><p class="mt-1 break-all font-mono text-xs text-surface-500">{organization.brokerDid}</p></div>
            <span class="rounded-full bg-surface-900 px-3 py-1 text-xs font-semibold text-white">{organization.plan}</span>
          </div>
          <p class="mt-4 text-sm text-surface-700">{planDescriptions[organization.plan]}</p>
          {#if organization.entitlements}
            <dl class="mt-5 grid gap-4 border-t border-surface-200 pt-5 sm:grid-cols-3">
              <div><dt class="text-xs text-surface-500">Managed accounts</dt><dd class="mt-1 text-sm font-semibold text-surface-900">{organization.usage.managedAccounts} / {organization.entitlements.maxManagedAccounts}</dd></div>
              <div><dt class="text-xs text-surface-500">Apps</dt><dd class="mt-1 text-sm font-semibold text-surface-900">{organization.usage.apps} / {organization.entitlements.maxApps}</dd></div>
              <div><dt class="text-xs text-surface-500">Requests per minute</dt><dd class="mt-1 text-sm font-semibold text-surface-900">{organization.entitlements.requestsPerMinute}</dd></div>
            </dl>
          {/if}
        </section>
      {/each}
    </div>
  {/if}

  <section class="mt-10 border-t border-surface-200 pt-8">
    <h2 class="text-lg font-semibold text-surface-900">Public plans</h2>
    <div class="mt-4 overflow-x-auto rounded-xl border border-surface-200 bg-white">
      <table class="w-full min-w-[640px] text-left text-sm">
        <thead class="bg-surface-100 text-surface-700"><tr><th class="px-4 py-3 font-semibold">Plan</th><th class="px-4 py-3 font-semibold">Managed accounts</th><th class="px-4 py-3 font-semibold">Policy & webhooks</th><th class="px-4 py-3 font-semibold">Eject</th></tr></thead>
        <tbody class="divide-y divide-surface-200 text-surface-700">
          <tr><th class="px-4 py-3 font-semibold text-surface-900">Free</th><td class="px-4 py-3">Starter limits</td><td class="px-4 py-3">Safe templates, basic lifecycle</td><td class="px-4 py-3 font-medium text-emerald-800">Always included</td></tr>
          <tr><th class="px-4 py-3 font-semibold text-surface-900">Pro</th><td class="px-4 py-3">Higher limits</td><td class="px-4 py-3">Configurable policy, full webhooks</td><td class="px-4 py-3 font-medium text-emerald-800">Always included</td></tr>
          <tr><th class="px-4 py-3 font-semibold text-surface-900">Enterprise</th><td class="px-4 py-3">Contracted limits</td><td class="px-4 py-3">Versioned custom policy and controls</td><td class="px-4 py-3 font-medium text-emerald-800">Always included</td></tr>
        </tbody>
      </table>
    </div>
  </section>
</div>

<style>@media (prefers-reduced-motion: reduce) { :global(.animate-pulse) { animation: none; } }</style>
