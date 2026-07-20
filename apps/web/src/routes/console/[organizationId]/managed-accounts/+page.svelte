<script lang="ts">
  import { getContext } from 'svelte';
  import { page } from '$app/stores';
  import { CONSOLE_SHELL, type ConsoleShellContext } from '$lib/console-shell';
  import { api, type ConsoleManagedAccount } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  const { overview } = getContext<ConsoleShellContext>(CONSOLE_SHELL);
  let currentOrganizationId = $derived($page.params.organizationId ?? '');

  let accounts = $state<ConsoleManagedAccount[]>([]);
  let nextCursor = $state<string | null>(null);
  let loading = $state(true);
  let loadingMore = $state(false);
  let error = $state('');
  let loadedFor = $state('');
  let selectedAccountId = $state<string | null>(null);

  async function loadAccounts(reset = true) {
    loading = reset;
    loadingMore = !reset;
    error = '';
    try {
      const result = await api.listConsoleManagedAccounts(currentOrganizationId, {
        limit: 12,
        cursor: reset ? undefined : nextCursor ?? undefined,
      });
      accounts = reset ? result.accounts : [...accounts, ...result.accounts];
      nextCursor = result.nextCursor;
      if (!selectedAccountId || reset) {
        selectedAccountId = accounts[0]?.managedAccountId ?? null;
      } else if (!accounts.some((account) => account.managedAccountId === selectedAccountId)) {
        selectedAccountId = accounts[0]?.managedAccountId ?? null;
      }
    } catch (caught: any) {
      error = caught.message || 'Could not load managed accounts.';
    } finally {
      loading = false;
      loadingMore = false;
    }
  }

  function statusCopy(account: ConsoleManagedAccount) {
    if (account.state === 'USER_OWNED') {
      return account.tenantAccess === 'REVOKED'
        ? 'Personal custody is active and tenant access is revoked.'
        : 'Personal custody is active, and tenant access revocation is still pending.';
    }
    if (account.state === 'EJECTING') {
      return 'The account is in flight between tenant custody and personal custody.';
    }
    if (account.state === 'FAILED') {
      return 'Provisioning or lifecycle activation failed. Review the account timeline.';
    }
    return 'The organization currently manages this account under the approved policy.';
  }

  function badgeClass(account: ConsoleManagedAccount) {
    if (account.state === 'USER_OWNED') return 'border-emerald-200 bg-emerald-50 text-emerald-700';
    if (account.state === 'EJECTING') return 'border-amber-200 bg-amber-50 text-amber-700';
    if (account.state === 'FAILED') return 'border-red-200 bg-red-50 text-red-700';
    return 'border-primary-200 bg-primary-50 text-primary-700';
  }

  $effect(() => {
    const orgId = currentOrganizationId;
    if (loadedFor !== orgId) {
      loadedFor = orgId;
      selectedAccountId = null;
      nextCursor = null;
      void loadAccounts(true);
    }
  });

  function selectedAccount() {
    return accounts.find((account) => account.managedAccountId === selectedAccountId) ?? accounts[0] ?? null;
  }
</script>

<svelte:head>
  <title>Managed accounts · OpenKey Console</title>
</svelte:head>

<div class="space-y-6">
  <Card class="space-y-4">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">Managed accounts</p>
        <h1 class="mt-2 text-3xl font-semibold tracking-[-0.04em] text-surface-900">Lifecycle state and custody details</h1>
        <p class="mt-3 max-w-2xl text-sm leading-6 text-surface-600">
          This list shows the tenant-managed view of each account. It explains the state, custody epoch, and tenant access status, but it never exposes a tenant-triggered eject button.
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <span class="rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-semibold text-surface-600">
          { $overview?.usage.managedAccounts ?? accounts.length } accounts
        </span>
        <Button variant="secondary" href="/dashboard/managed-accounts">Open user eject path</Button>
      </div>
    </div>
    <div class="rounded-2xl border border-dotted border-surface-200 bg-white px-4 py-3 text-sm leading-6 text-surface-600">
      The personal OpenKey Account owns the eject action. The console only explains the state and links out to the user-owned path.
    </div>
  </Card>

  {#if error}
    <Card class="border-red-200 bg-red-50/60">
      <p class="text-sm font-medium text-red-700">{error}</p>
    </Card>
  {/if}

  {#if loading}
    <Card class="space-y-3" aria-label="Loading managed accounts">
      <div class="h-24 rounded-2xl bg-surface-100"></div>
      <div class="h-24 rounded-2xl bg-surface-100"></div>
    </Card>
  {:else if accounts.length === 0}
    <Card class="space-y-3">
      <h2 class="text-lg font-semibold text-surface-900">No managed accounts yet</h2>
      <p class="max-w-2xl text-sm leading-6 text-surface-600">
        Register the first account from a tenant app and return here to inspect the resulting state, epoch, and ownership path.
      </p>
      <div class="flex flex-wrap gap-2">
        <Button href={`/console/${$page.params.organizationId}/apps`}>Open apps</Button>
        <Button variant="secondary" href={`/console/${$page.params.organizationId}/credentials`}>Issue credential</Button>
      </div>
    </Card>
  {:else}
    <div class="grid gap-6 xl:grid-cols-[1fr_0.9fr]">
      <Card class="space-y-4">
        <div class="flex items-center justify-between gap-3">
          <div>
            <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Accounts</h2>
            <p class="mt-1 text-sm leading-6 text-surface-600">Select a row to see more state and custody details.</p>
          </div>
          <Button variant="secondary" onclick={() => void loadAccounts(true)}>Reload</Button>
        </div>

        <div class="space-y-3">
          {#each accounts as account}
            <button
              type="button"
              class={`w-full rounded-2xl border p-4 text-left transition-colors ${
                selectedAccountId === account.managedAccountId
                  ? 'border-primary-200 bg-primary-50/60'
                  : 'border-surface-200 bg-white hover:border-surface-300 hover:bg-surface-50'
              }`}
              onclick={() => { selectedAccountId = account.managedAccountId; }}
            >
              <div class="flex flex-wrap items-start justify-between gap-3">
                <div class="min-w-0">
                  <div class="flex flex-wrap items-center gap-2">
                    <h3 class="text-base font-semibold text-surface-900">{account.externalUserId}</h3>
                    <span class={`rounded-full border px-2.5 py-1 text-xs font-semibold ${badgeClass(account)}`}>
                      {account.state}
                    </span>
                  </div>
                  <p class="mt-2 font-mono text-xs text-surface-500 break-all">{account.ownerDid}</p>
                  <p class="mt-2 text-sm leading-6 text-surface-600">{statusCopy(account)}</p>
                </div>
                <div class="text-right text-xs text-surface-500">
                  <div>Epoch {account.custodyEpoch}</div>
                  <div class="mt-1">{account.tenantAccess}</div>
                </div>
              </div>
            </button>
          {/each}
        </div>

        {#if nextCursor}
          <div class="flex justify-center">
            <Button variant="secondary" disabled={loadingMore} onclick={() => void loadAccounts(false)}>
              {loadingMore ? 'Loading more...' : 'Load more'}
            </Button>
          </div>
        {/if}
      </Card>

      <Card class="space-y-4">
        {#if selectedAccount()}
          {@const account = selectedAccount()}
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">Selected account</p>
              <h2 class="mt-2 text-xl font-semibold tracking-[-0.03em] text-surface-900">{account.externalUserId}</h2>
              <p class="mt-2 text-sm leading-6 text-surface-600">{statusCopy(account)}</p>
            </div>
            <span class={`rounded-full border px-3 py-1 text-xs font-semibold ${badgeClass(account)}`}>
              {account.state}
            </span>
          </div>

          <dl class="grid gap-3 sm:grid-cols-2">
            <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
              <dt class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Address</dt>
              <dd class="mt-2 break-all font-mono text-sm text-surface-900">{account.address}</dd>
            </div>
            <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
              <dt class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Owner DID</dt>
              <dd class="mt-2 break-all font-mono text-sm text-surface-900">{account.ownerDid}</dd>
            </div>
            <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
              <dt class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Custody epoch</dt>
              <dd class="mt-2 text-sm font-semibold text-surface-900">{account.custodyEpoch}</dd>
            </div>
            <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
              <dt class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Tenant access</dt>
              <dd class="mt-2 text-sm font-semibold text-surface-900">{account.tenantAccess}</dd>
            </div>
            <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4 sm:col-span-2">
              <dt class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Policy template / version</dt>
              <dd class="mt-2 text-sm font-semibold text-surface-900">{account.policyTemplate} · v{account.policyVersion}</dd>
            </div>
            <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4 sm:col-span-2">
              <dt class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Tenant-parent delegation</dt>
              <dd class="mt-2 break-all font-mono text-xs text-surface-900">{account.tenantParentDelegationCid ?? 'Not yet provisioned'}</dd>
            </div>
          </dl>

          <div class="rounded-2xl border border-dotted border-surface-200 bg-white p-4 text-sm leading-6 text-surface-600">
            The user-owned eject path is in the personal <a class="font-semibold text-primary-700 underline-offset-4 hover:underline" href="/dashboard/managed-accounts">OpenKey Account</a>. The console does not offer a tenant-triggered eject control.
          </div>
        {:else}
          <div class="rounded-2xl border border-dotted border-surface-200 bg-surface-50 p-6 text-sm leading-6 text-surface-600">
            Select an account to inspect custody and lifecycle details.
          </div>
        {/if}
      </Card>
    </div>
  {/if}
</div>
