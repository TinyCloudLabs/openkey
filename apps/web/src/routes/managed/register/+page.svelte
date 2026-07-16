<script lang="ts">
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type HostedRegistrationIntent } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';

  const session = authClient.useSession();
  const token = $derived($page.url.searchParams.get('intent') ?? '');
  let intent = $state<HostedRegistrationIntent | null>(null);
  let account = $state<{ managedAccountId: string; address: string; ownerDid: string; state: string; custodyEpoch: number } | null>(null);
  let loading = $state(true);
  let completing = $state(false);
  let error = $state('');
  let loadedToken = '';

  $effect(() => {
    if (token && token !== loadedToken) {
      loadedToken = token;
      loadIntent();
    } else if (!token) {
      loading = false;
      error = 'This registration link is incomplete.';
    }
  });

  async function loadIntent() {
    loading = true;
    error = '';
    try {
      intent = (await api.getHostedRegistrationIntent(token)).intent;
    } catch (e: any) {
      error = e.message || 'This registration link is invalid or expired.';
    } finally {
      loading = false;
    }
  }

  async function completeRegistration() {
    completing = true;
    error = '';
    try {
      account = (await api.completeHostedRegistration(token)).account;
    } catch (e: any) {
      error = e.code === 'OWNER_PASSKEY_REQUIRED'
        ? 'Add an OpenKey passkey before this account can be managed.'
        : e.message || 'We could not create the managed account.';
    } finally {
      completing = false;
    }
  }

  function returnTo() {
    return `/managed/register?intent=${encodeURIComponent(token)}`;
  }

  function tenantLabel() {
    const label = intent?.metadata?.displayName;
    return typeof label === 'string' ? label : null;
  }
</script>

<svelte:head>
  <title>Set up your managed OpenKey</title>
</svelte:head>

<main class="min-h-screen bg-surface-50 px-4 py-10 sm:py-16">
  <div class="mx-auto w-full max-w-2xl">
    <a href="/" class="mb-10 inline-flex items-center gap-2 text-sm font-semibold text-surface-900 no-underline">
      <span class="flex h-8 w-8 items-center justify-center rounded-xl bg-surface-900 text-white" aria-hidden="true">⌁</span>
      OpenKey
    </a>

    {#if loading}
      <div class="space-y-4" aria-live="polite" aria-label="Loading registration">
        <div class="h-8 w-2/3 animate-pulse rounded-lg bg-surface-200"></div>
        <div class="h-24 animate-pulse rounded-xl bg-surface-100"></div>
      </div>
    {:else if error && !intent}
      <section class="rounded-2xl bg-white p-6 shadow-sm sm:p-8" role="alert">
        <h1 class="text-2xl font-semibold text-surface-900">Registration unavailable</h1>
        <p class="mt-3 max-w-prose text-surface-600">{error}</p>
      </section>
    {:else if account && intent}
      <section class="rounded-2xl bg-white p-6 shadow-sm sm:p-8" aria-live="polite">
        <div class="mb-6 flex h-11 w-11 items-center justify-center rounded-full bg-emerald-100 text-emerald-800" aria-hidden="true">✓</div>
        <h1 class="text-2xl font-semibold text-surface-900">Your managed account is ready</h1>
        <p class="mt-2 max-w-prose text-surface-600">
          {intent.organization.name} can now use the policy-bounded access you approved. Your passkey remains under your control.
        </p>

        <dl class="my-7 divide-y divide-surface-200 border-y border-surface-200">
          <div class="py-4 sm:flex sm:items-start sm:justify-between sm:gap-8">
            <dt class="text-sm font-medium text-surface-600">Ethereum address</dt>
            <dd class="mt-1 break-all font-mono text-sm text-surface-900 sm:mt-0 sm:text-right">{account.address}</dd>
          </div>
          <div class="py-4 sm:flex sm:items-start sm:justify-between sm:gap-8">
            <dt class="text-sm font-medium text-surface-600">Custody</dt>
            <dd class="mt-1 text-sm font-medium text-surface-900 sm:mt-0">Managed by {intent.organization.name}</dd>
          </div>
          <div class="py-4 sm:flex sm:items-start sm:justify-between sm:gap-8">
            <dt class="text-sm font-medium text-surface-600">Your exit right</dt>
            <dd class="mt-1 max-w-sm text-sm text-surface-700 sm:mt-0 sm:text-right">Transfer to personal OpenKey custody at any time, without changing this address.</dd>
          </div>
        </dl>

        <Button href={intent.redirectUri} size="lg" class="w-full sm:w-auto">Continue to {intent.organization.name}</Button>
      </section>
    {:else if intent}
      <section class="rounded-2xl bg-white p-6 shadow-sm sm:p-8">
        <div class="flex flex-wrap items-center gap-2 text-sm text-surface-600">
          <span class="rounded-full bg-surface-100 px-3 py-1 font-medium text-surface-800">{intent.organization.plan}</span>
          <span>Registration requested by {intent.organization.name}</span>
        </div>
        <h1 class="mt-6 text-3xl font-semibold tracking-tight text-surface-900">Create your OpenKey account</h1>
        <p class="mt-3 max-w-prose text-base leading-7 text-surface-600">
          {intent.organization.name} will manage this account through a restricted TinyCloud policy. You keep an independent OpenKey passkey and can leave from OpenKey whenever you choose.
        </p>

        {#if tenantLabel()}
          <p class="mt-5 rounded-xl bg-surface-100 px-4 py-3 text-sm text-surface-700">Account label: {tenantLabel()}</p>
        {/if}

        <div class="my-7 border-y border-surface-200 py-5">
          <h2 class="text-sm font-semibold text-surface-900">What stays yours</h2>
          <ul class="mt-3 space-y-2 text-sm text-surface-700">
            <li class="flex gap-3"><span aria-hidden="true">✓</span><span>Your OpenKey passkey and recovery authority</span></li>
            <li class="flex gap-3"><span aria-hidden="true">✓</span><span>The same Ethereum address, DID, TinyCloud spaces, and data after eject</span></li>
            <li class="flex gap-3"><span aria-hidden="true">✓</span><span>The unilateral right to transfer to personal OpenKey custody</span></li>
          </ul>
        </div>

        {#if error}
          <div class="mb-5 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" role="alert">{error}</div>
        {/if}

        {#if $session.data}
          <Button onclick={completeRegistration} disabled={completing} size="lg" class="w-full">
            {completing ? 'Creating account…' : `Approve ${intent.organization.name} management`}
          </Button>
          {#if error.includes('passkey')}
            <Button href={`/auth/register?step=passkey&returnTo=${encodeURIComponent(returnTo())}`} variant="secondary" class="mt-3 w-full">Add a passkey</Button>
          {/if}
        {:else}
          <div class="flex flex-col gap-3 sm:flex-row">
            <Button href={`/auth/register?returnTo=${encodeURIComponent(returnTo())}`} size="lg" class="w-full">Create OpenKey</Button>
            <Button href={`/auth/login?returnTo=${encodeURIComponent(returnTo())}`} variant="secondary" size="lg" class="w-full">Sign in</Button>
          </div>
        {/if}

        <p class="mt-5 text-xs leading-5 text-surface-500">
          Demo security note: custody events are signed and audited, but rollback-resistant external witnessing is post-demo hardening.
        </p>
      </section>
    {/if}
  </div>
</main>

<style>
  @media (prefers-reduced-motion: reduce) {
    :global(.animate-pulse) { animation: none; }
  }
</style>
