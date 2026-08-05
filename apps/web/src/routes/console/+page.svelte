<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import { api, type OrganizationSummary } from '$lib/api';
  import { accountHref } from '$lib/console-host';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  const session = authClient.useSession();
  let organizations = $state<OrganizationSummary[]>([]);
  let name = $state('');
  let error = $state('');
  let loading = $state(true);
  let creating = $state(false);
  let loaded = false;
  $effect(() => { if (!$session.isPending && $session.data && !loaded) { loaded = true; void load(); } if (!$session.isPending && !$session.data) loading = false; });
  async function load() { try { organizations = (await api.listConsoleOrganizations()).organizations; } catch (caught: any) { error = caught.message ?? 'Could not load organizations.'; } finally { loading = false; } }
  async function createOrganization() { if (!name.trim()) return; creating = true; error = ''; try { const result = await api.createOrganization(name.trim()); await goto(`/console/${result.organization.id}`); } catch (caught: any) { error = caught.message ?? 'Could not create organization.'; } finally { creating = false; } }
</script>

<svelte:head><title>OpenKey Console</title><meta name="description" content="Developer Organizations and OAuth applications." /></svelte:head>

<main class="mx-auto max-w-5xl px-4 py-10 sm:px-6">
  {#if !$session.isPending && !$session.data}
    <Card class="mx-auto max-w-lg text-center"><h1 class="text-3xl font-semibold">Sign in to the developer console</h1><p class="mt-3 text-surface-600">Organizations manage teams and OAuth application configuration.</p><Button class="mt-6" href={accountHref(`/auth/login?redirect=${encodeURIComponent(window.location.href)}`)}>Sign in</Button></Card>
  {:else}
    <div class="grid gap-6 lg:grid-cols-2"><Card><p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">Developer Organizations</p><h1 class="mt-3 text-3xl font-semibold">Teams and OAuth apps</h1><p class="mt-3 text-sm leading-6 text-surface-600">Organizations never manage user keys or TinyCloud data.</p><form class="mt-6 flex gap-2" onsubmit={(event) => { event.preventDefault(); void createOrganization(); }}><Input bind:value={name} placeholder="Organization name" required /><Button type="submit" disabled={creating}>{creating ? 'Creating…' : 'Create'}</Button></form>{#if error}<p class="mt-3 text-sm text-red-700">{error}</p>{/if}</Card><section><h2 class="text-xl font-semibold">Your organizations</h2>{#if loading}<p class="mt-3 text-surface-600">Loading…</p>{:else if organizations.length === 0}<Card class="mt-3"><p class="text-surface-600">Create an organization to configure OAuth applications with your team.</p></Card>{:else}<div class="mt-3 space-y-3">{#each organizations as organization}<Card><h3 class="font-semibold">{organization.name}</h3><p class="mt-1 text-sm text-surface-600">{organization.usage.apps} apps · {organization.usage.members} members</p><Button class="mt-4" href={`/console/${organization.id}`}>Open console</Button></Card>{/each}</div>{/if}</section></div>
  {/if}
</main>
