<script lang="ts">
  import { page } from '$app/stores';
  import { getContext } from 'svelte';
  import { api, type ConsoleMember } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';
  import { CONSOLE_SHELL, type ConsoleShellContext } from '$lib/console-shell';

  const { overview, refresh } = getContext<ConsoleShellContext>(CONSOLE_SHELL);

  let currentOrganizationId = $derived($page.params.organizationId ?? '');
  let members = $state<ConsoleMember[]>([]);
  let address = $state('');
  let loading = $state(true);
  let adding = $state(false);
  let error = $state('');
  let addError = $state('');
  let confirmation = $state('');
  let loadedFor = $state('');
  let canAdd = $derived($overview?.organization.role === 'ADMIN');

  function shortAddress(value: string | null): string {
    if (!value) return 'No active personal address';
    return `${value.slice(0, 8)}…${value.slice(-6)}`;
  }

  async function loadMembers() {
    const organizationId = currentOrganizationId;
    if (!organizationId) return;
    loading = true;
    error = '';
    try {
      const result = await api.listConsoleMembers(organizationId);
      members = result.members;
      loadedFor = organizationId;
    } catch (caught: any) {
      error = caught?.message || 'Could not load organization members.';
    } finally {
      loading = false;
    }
  }

  async function addAdministrator() {
    const candidate = address.trim();
    if (!candidate) return;
    adding = true;
    addError = '';
    confirmation = '';
    try {
      const result = await api.addConsoleAdmin(currentOrganizationId, candidate);
      const existingIndex = members.findIndex((member) => member.id === result.member.id);
      if (existingIndex >= 0) {
        members[existingIndex] = result.member;
      } else {
        members = [...members, result.member];
      }
      address = '';
      confirmation = `${result.member.email} can now administer this organization.`;
      await refresh();
    } catch (caught: any) {
      addError = caught?.message || 'Could not add this administrator.';
    } finally {
      adding = false;
    }
  }

  $effect(() => {
    const organizationId = currentOrganizationId;
    if (organizationId && loadedFor !== organizationId) {
      void loadMembers();
    }
  });
</script>

<svelte:head>
  <title>Members · OpenKey Console</title>
</svelte:head>

<div class="space-y-6">
  <div class="max-w-3xl">
    <h1 class="text-3xl font-semibold tracking-[-0.04em] text-surface-900 text-balance">Organization members</h1>
    <p class="mt-3 max-w-2xl text-sm leading-6 text-surface-600">
      Administrators can view and manage every app in this organization. Add someone only after they have signed in to OpenKey and linked the Ethereum address they control.
    </p>
  </div>

  {#if canAdd}
    <Card class="space-y-4">
      <div>
        <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Add an administrator</h2>
        <p class="mt-1 max-w-2xl text-sm leading-6 text-surface-600">
          OpenKey resolves the address to a verified account. A bare or unlinked address cannot receive access.
        </p>
      </div>

      <form class="flex flex-col gap-3 sm:flex-row sm:items-end" onsubmit={(event) => { event.preventDefault(); void addAdministrator(); }}>
        <div class="min-w-0 flex-1 space-y-2">
          <label for="administrator-address" class="text-sm font-semibold text-surface-900">Linked Ethereum address</label>
          <Input
            id="administrator-address"
            bind:value={address}
            placeholder="0x…"
            autocomplete="off"
            spellcheck={false}
            required
          />
        </div>
        <Button type="submit" disabled={adding || !address.trim()}>
          {adding ? 'Adding…' : 'Add administrator'}
        </Button>
      </form>

      {#if addError}
        <p role="alert" class="text-sm leading-6 text-red-700">{addError}</p>
      {:else if confirmation}
        <p role="status" class="text-sm leading-6 text-primary-700">{confirmation}</p>
      {/if}
    </Card>
  {:else}
    <div class="rounded-2xl border border-surface-200 bg-surface-50 px-4 py-3 text-sm leading-6 text-surface-600">
      You can view the member roster. Only an administrator can grant access.
    </div>
  {/if}

  <section aria-labelledby="member-roster-heading" class="space-y-3">
    <div class="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h2 id="member-roster-heading" class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Current access</h2>
        <p class="mt-1 text-sm leading-6 text-surface-600">
          {members.length} of {$overview?.entitlements?.maxOrganizationMembers ?? members.length} organization seats are in use.
        </p>
      </div>
      <Button variant="secondary" onclick={() => void loadMembers()} disabled={loading}>
        {loading ? 'Refreshing…' : 'Refresh'}
      </Button>
    </div>

    {#if error}
      <Card>
        <p role="alert" class="text-sm text-red-700">{error}</p>
      </Card>
    {:else if loading}
      <Card>
        <p class="text-sm text-surface-600">Loading members…</p>
      </Card>
    {:else if members.length === 0}
      <Card>
        <h3 class="font-semibold text-surface-900">No active members</h3>
        <p class="mt-2 text-sm leading-6 text-surface-600">This organization has no active membership records.</p>
      </Card>
    {:else}
      <div class="overflow-hidden rounded-2xl border border-surface-200 bg-white">
        <ul class="divide-y divide-surface-200">
          {#each members as member (member.id)}
            <li class="flex flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:justify-between">
              <div class="min-w-0">
                <p class="truncate font-semibold text-surface-900">{member.name || member.email}</p>
                <p class="mt-1 truncate text-sm text-surface-600">{member.email}</p>
              </div>
              <div class="flex flex-wrap items-center gap-2 sm:justify-end">
                <span class="rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-semibold text-surface-700">
                  {member.role}
                </span>
              </div>
            </li>
          {/each}
        </ul>
      </div>
    {/if}
  </section>
</div>
