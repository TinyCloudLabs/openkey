<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import { api, type OwnerManagedAccount } from '$lib/api';
  import { embedSignInPasskey } from '$lib/embed-passkey';
  import Button from '$lib/components/ui/button.svelte';

  const session = authClient.useSession();
  let accounts = $state<OwnerManagedAccount[]>([]);
  let loading = $state(true);
  let error = $state('');
  let activeId = $state<string | null>(null);
  let passkeyReady = $state(false);
  let verifying = $state(false);
  let ejecting = $state(false);
  let idempotencyKey = $state('');
  let loaded = false;

  $effect(() => {
    if (!$session.isPending && !$session.data) goto('/auth/login');
    if (!$session.isPending && $session.data && !loaded) {
      loaded = true;
      loadAccounts();
    }
  });

  async function loadAccounts() {
    loading = true;
    error = '';
    try {
      accounts = (await api.listManagedAccounts()).accounts;
    } catch (e: any) {
    error = e.message || 'Could not load connected apps.';
    } finally {
      loading = false;
    }
  }

  function beginEject(account: OwnerManagedAccount) {
    activeId = account.managedAccountId;
    passkeyReady = false;
    error = '';
    idempotencyKey = crypto.randomUUID();
  }

  function cancelEject() {
    activeId = null;
    passkeyReady = false;
    idempotencyKey = '';
  }

  async function verifyPasskey() {
    verifying = true;
    error = '';
    try {
      await embedSignInPasskey();
      passkeyReady = true;
    } catch (e: any) {
      error = e.message || 'Passkey verification failed.';
    } finally {
      verifying = false;
    }
  }

  async function confirmEject(account: OwnerManagedAccount) {
    ejecting = true;
    error = '';
    try {
      await api.ejectManagedAccount(account.managedAccountId, account.custodyEpoch, idempotencyKey);
      cancelEject();
      await loadAccounts();
    } catch (e: any) {
      error = e.message || 'Custody transfer failed. No changes were made.';
    } finally {
      ejecting = false;
    }
  }

  function shortAddress(address: string) {
    return `${address.slice(0, 8)}…${address.slice(-6)}`;
  }
</script>

<svelte:head><title>Connected apps · OpenKey</title></svelte:head>

<div class="mx-auto max-w-4xl px-4 py-10">
  <div class="mb-8 flex flex-wrap items-end justify-between gap-4">
    <div>
      <h1 class="text-2xl font-semibold text-surface-900">Connected apps</h1>
      <p class="mt-2 max-w-2xl text-sm leading-6 text-surface-600">
        Accounts and app relationships currently managed by your personal OpenKey Account, plus the path back to personal custody.
      </p>
    </div>
    <div class="flex flex-wrap gap-2">
      <Button variant="secondary" href="/dashboard">Back to account</Button>
      <Button href="/console">Open console</Button>
    </div>
  </div>

  <div aria-live="polite">
    {#if error}
      <div class="mb-5 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" role="alert">{error}</div>
    {/if}

    {#if loading}
      <div class="space-y-3" aria-label="Loading connected apps">
        <div class="h-24 animate-pulse rounded-xl bg-surface-100"></div>
        <div class="h-24 animate-pulse rounded-xl bg-surface-100"></div>
      </div>
    {:else if accounts.length === 0}
      <section class="rounded-2xl bg-white p-8 shadow-sm">
        <h2 class="text-lg font-semibold text-surface-900">No connected apps yet</h2>
        <p class="mt-2 max-w-prose text-sm leading-6 text-surface-600">
          When a tenant app connects to your OpenKey account, it will appear here with its custody state and exit status.
        </p>
      </section>
    {:else}
      <section class="overflow-hidden rounded-2xl bg-white shadow-sm">
        {#each accounts as account, index}
          <article class:border-t={index > 0} class="border-surface-200 p-5 sm:p-6">
            <div class="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
              <div class="min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <h2 class="font-semibold text-surface-900">{account.managedBy}</h2>
                  {#if account.custody === 'USER_OWNED'}
                    <span class="rounded-full bg-emerald-100 px-2.5 py-1 text-xs font-semibold text-emerald-800">Personal custody</span>
                  {:else}
                    <span class="rounded-full bg-violet-100 px-2.5 py-1 text-xs font-semibold text-violet-800">App managed</span>
                  {/if}
                </div>
                <p class="mt-2 font-mono text-sm text-surface-700" title={account.address}>{shortAddress(account.address)}</p>
                <p class="mt-2 text-sm text-surface-600">
                  {#if account.custody === 'USER_OWNED' && account.tenantAccess === 'PENDING'}
                    Personal custody is active. Tenant access revocation is still pending on a known node.
                  {:else if account.custody === 'USER_OWNED'}
                    Personal custody is active and known tenant access has been revoked.
                  {:else}
                    {account.managedBy} can request only the policy-bounded OpenKey access you approved.
                  {/if}
                </p>
              </div>

              {#if account.custody !== 'USER_OWNED' && activeId !== account.managedAccountId}
                <Button variant="secondary" onclick={() => beginEject(account)}>Leave {account.managedBy}</Button>
              {:else if account.custody === 'USER_OWNED' && account.tenantAccess === 'PENDING'}
                <Button variant="secondary" onclick={loadAccounts}>Refresh status</Button>
              {/if}
            </div>

            {#if activeId === account.managedAccountId}
              <div class="mt-6 border-t border-surface-200 pt-6">
                <h3 class="text-base font-semibold text-surface-900">Transfer this account to personal OpenKey custody?</h3>
                <p class="mt-2 max-w-2xl text-sm leading-6 text-surface-700">
                  OpenKey will stop signing for {account.managedBy} immediately after the custody transaction. Your address, DID, spaces, and encrypted data will not change. This transfer cannot be reversed in v1.
                </p>
                <dl class="mt-4 flex flex-col gap-2 text-sm sm:flex-row sm:gap-8">
                  <div><dt class="text-surface-500">Current epoch</dt><dd class="font-medium text-surface-900">{account.custodyEpoch}</dd></div>
                  <div><dt class="text-surface-500">Address after transfer</dt><dd class="font-mono text-surface-900">{shortAddress(account.address)}</dd></div>
                </dl>

                <div class="mt-5 flex flex-col gap-3 sm:flex-row">
                  {#if !passkeyReady}
                    <Button onclick={verifyPasskey} disabled={verifying}>{verifying ? 'Verifying…' : 'Verify with passkey'}</Button>
                  {:else}
                    <Button onclick={() => confirmEject(account)} disabled={ejecting}>{ejecting ? 'Transferring custody…' : 'Transfer custody now'}</Button>
                  {/if}
                  <Button variant="ghost" onclick={cancelEject} disabled={verifying || ejecting}>Cancel</Button>
                </div>
                {#if passkeyReady}
                  <p class="mt-3 text-sm font-medium text-emerald-800">Passkey verified. Review the details once more, then transfer custody.</p>
                {/if}
              </div>
            {/if}
          </article>
        {/each}
      </section>
    {/if}
  </div>

  <p class="mt-6 text-xs leading-5 text-surface-500">
    “Personal custody” means the unchanged key remains protected inside OpenKey’s TEE. It is not private-key export or external self-custody. For the organizational console, use the console-managed app and credential flows instead of this personal eject path.
  </p>
</div>

<style>
  @media (prefers-reduced-motion: reduce) {
    :global(.animate-pulse) { animation: none; }
  }
</style>
