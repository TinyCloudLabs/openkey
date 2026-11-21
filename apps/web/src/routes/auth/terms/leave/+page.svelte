<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { api, type ConnectedIdentityApp, type ConnectedMcpApp, type TinyCloudManageKeyApp } from '$lib/api';
  import { authClient } from '$lib/auth-client';
  import { loadTermsStatus } from '$lib/terms';
  import { optionsHref, termsPageFrom } from '$lib/terms-leave';
  import { renewalLeaseCopy, type RenewalLease } from '$lib/renewal-leases';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import ConnectedIdentityApps from '../../../dashboard/settings/ConnectedIdentityApps.svelte';
  import ConnectedMcpApps from '../../../dashboard/settings/ConnectedMcpApps.svelte';
  import DeleteAccountSection from '../DeleteAccountSection.svelte';
  import RenewalLeases from '../../../dashboard/settings/RenewalLeases.svelte';
  import TinyCloudAppDisconnects from '../../../dashboard/settings/TinyCloudAppDisconnects.svelte';

  // TC-3232, page 3 of the ways out, from Other options: disconnect apps, stop renewals, delete the
  // account, all without agreeing to the Terms. The API lets an account that has not accepted read and
  // do exactly these; an account that has accepted has them all in Settings.
  const back = optionsHref(termsPageFrom($page.url.searchParams.get('returnTo')));

  let ready = $state(false);
  let signingApps = $state<TinyCloudManageKeyApp[]>([]);
  let mcpApps = $state<ConnectedMcpApp[]>([]);
  let identityApps = $state<ConnectedIdentityApp[]>([]);
  let appsError = $state('');
  let leases = $state<RenewalLease[]>([]);
  let leasesError = $state('');
  // Like Settings, a section stays once shown, so its "disconnected" or "stopped" notice stays with it.
  let shown = $state({ signing: false, mcp: false, leases: false });

  const noApps = $derived(!shown.signing && !shown.mcp && identityApps.length === 0);

  async function loadApps() {
    appsError = '';
    try {
      const result = await api.listTinyCloudManageKeyApps();
      signingApps = result.apps.filter((app) => app.nativeDelegation);
      mcpApps = result.mcpApps ?? [];
      identityApps = result.identityApps ?? [];
      shown.signing ||= signingApps.length > 0;
      shown.mcp ||= mcpApps.length > 0;
    } catch {
      appsError = 'Couldn’t load your connected apps. Refresh the page to try again.';
    }
  }

  async function loadLeases() {
    leasesError = '';
    try {
      leases = (await api.listRenewalLeases()).leases;
      shown.leases ||= leases.length > 0;
    } catch {
      leasesError = renewalLeaseCopy.loadFailed;
    }
  }

  onMount(async () => {
    const session = await authClient.getSession().catch(() => null);
    if (!session?.data) {
      window.location.assign('/auth/login');
      return;
    }
    const status = await loadTermsStatus().catch(() => null);
    if (status && !status.requiresAcceptance) {
      await goto('/dashboard/settings');
      return;
    }
    await Promise.all([loadApps(), loadLeases()]);
    ready = true;
  });
</script>

<svelte:head>
  <title>Disconnect apps · OpenKey</title>
  <meta name="robots" content="noindex" />
</svelte:head>

<div class="mx-auto max-w-2xl px-4 py-8" data-testid="terms-leave">
  <div class="mb-6">
    <a href={back} class="text-sm text-surface-500 transition-colors hover:text-surface-700">&larr; Other options</a>
  </div>

  <h1 class="text-2xl font-bold text-surface-900">Disconnect apps</h1>
  <p class="mt-2 text-sm text-surface-500">You don’t need to agree to the Terms to disconnect apps, stop renewals or delete your account.</p>

  {#if !ready}
    <p class="mt-8 text-sm text-surface-400">Loading…</p>
  {:else}
    <section class="mt-8" aria-labelledby="leave-apps-heading">
      <h2 id="leave-apps-heading" class="text-xl font-semibold text-surface-900">Connected apps</h2>
      <p class="mt-1 text-sm text-surface-500">Disconnecting stops the app from getting new access. Permissions you set to renew keep renewing until you stop them under Renewing permissions. On the web and in the CLI, a signing app keeps the access it already has until it runs out. A phone app signs you out the next time it renews, unless you agree to the Terms first.</p>
      {#if appsError}
        <p role="alert" class="mt-4 text-sm text-red-600">{appsError}</p>
      {:else if noApps}
        <p class="mt-4 text-sm text-surface-500">No apps are connected to your account.</p>
      {/if}
    </section>

    {#if shown.signing}
      <Card id="connected-tinycloud-apps" class="mt-6">
        <h2 class="text-xl font-semibold text-surface-900">Connected TinyCloud apps</h2>
        <TinyCloudAppDisconnects apps={signingApps} onchanged={loadApps} />
      </Card>
    {/if}
    {#if shown.mcp}
      <Card id="connected-mcp-apps" class="mt-6">
        <ConnectedMcpApps apps={mcpApps} onchanged={loadApps} />
      </Card>
    {/if}
    <ConnectedIdentityApps apps={identityApps} onchanged={loadApps} />

    {#if leasesError}
      <Card class="mt-6"><p role="alert" class="text-sm text-red-600">{leasesError}</p></Card>
    {:else if shown.leases}
      <Card id="renewing-permissions" class="mt-6">
        <RenewalLeases {leases} onchanged={loadLeases} />
      </Card>
    {/if}

    <DeleteAccountSection />

    <div class="mt-8">
      <Button variant="secondary" href={back}>Back to other options</Button>
    </div>
  {/if}
</div>
