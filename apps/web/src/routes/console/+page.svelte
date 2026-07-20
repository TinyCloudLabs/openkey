<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import { api, type OrganizationSummary } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  const session = authClient.useSession();

  let organizations = $state<OrganizationSummary[]>([]);
  let loading = $state(true);
  let error = $state('');
  let loadingKeys = $state(true);
  let recommendedBrokerDid = $state('');
  let useAdvancedBrokerDid = $state(false);
  let manualBrokerDid = $state('');
  let creating = $state(false);
  let organizationName = $state('');
  let loaded = false;

  $effect(() => {
    if ($session.isPending) return;
    if (!$session.data) {
      loading = false;
      loadingKeys = false;
      return;
    }
    if (!loaded) {
      loaded = true;
      void load();
    }
  });

  async function load() {
    loading = true;
    loadingKeys = true;
    error = '';

    const [organizationResult, keysResult] = await Promise.allSettled([
      api.listConsoleOrganizations(),
      api.listKeys(),
    ]);

    if (organizationResult.status === 'fulfilled') {
      organizations = organizationResult.value.organizations;
    } else {
      error = organizationResult.reason?.message || 'Could not load organizations.';
    }

    if (keysResult.status === 'fulfilled') {
      const primaryKey = keysResult.value.keys.find((key) => !key.archivedAt) ?? keysResult.value.keys[0];
      recommendedBrokerDid = primaryKey ? `did:pkh:eip155:1:${primaryKey.address}` : '';
      if (!useAdvancedBrokerDid && recommendedBrokerDid) {
        manualBrokerDid = recommendedBrokerDid;
      }
    } else if (!error) {
      error = keysResult.reason?.message || 'Could not derive a recommended broker DID.';
    }

    loading = false;
    loadingKeys = false;
  }

  async function createOrganization() {
    creating = true;
    error = '';

    const brokerDid = useAdvancedBrokerDid ? manualBrokerDid.trim() : recommendedBrokerDid.trim();
    if (!organizationName.trim()) {
      error = 'Enter an organization name.';
      creating = false;
      return;
    }
    if (!brokerDid) {
      error = 'A broker DID is required to create an organization.';
      creating = false;
      return;
    }

    try {
      const result = await api.createOrganization(organizationName.trim(), brokerDid);
      organizationName = '';
      manualBrokerDid = recommendedBrokerDid;
      organizations = [...organizations, { id: result.organization.id, name: result.organization.name, role: 'ADMIN', plan: 'FREE', billingState: 'FREE', brokerDid, entitlements: null, usage: { apps: 0, managedAccounts: 0, members: 1 } }];
      goto(`/console/${result.organization.id}`);
    } catch (e: any) {
      error = e.message || 'Could not create the organization.';
    } finally {
      creating = false;
    }
  }

  function selectBrokerDidMode(nextValue: boolean) {
    useAdvancedBrokerDid = nextValue;
    if (!nextValue && recommendedBrokerDid) {
      manualBrokerDid = recommendedBrokerDid;
    }
  }
</script>

<svelte:head>
  <title>OpenKey Console</title>
  <meta name="description" content="Select or create an OpenKey organization console." />
</svelte:head>

<div class="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
  {#if $session.isPending || loading}
    <div class="grid gap-6 lg:grid-cols-[1.05fr_0.95fr]">
      <Card class="space-y-4">
        <div class="h-4 w-32 rounded-full bg-surface-100"></div>
        <div class="h-11 w-3/4 rounded-2xl bg-surface-100"></div>
        <div class="h-16 rounded-2xl bg-surface-100"></div>
        <div class="h-24 rounded-2xl bg-surface-100"></div>
      </Card>
      <Card class="space-y-4">
        <div class="h-4 w-36 rounded-full bg-surface-100"></div>
        <div class="h-10 rounded-2xl bg-surface-100"></div>
        <div class="h-10 rounded-2xl bg-surface-100"></div>
        <div class="h-10 w-40 rounded-full bg-surface-100"></div>
      </Card>
    </div>
  {:else if !$session.data}
    <div class="mx-auto flex min-h-[70vh] max-w-lg items-center">
      <Card class="w-full text-center">
        <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">OpenKey Console</p>
        <h1 class="mt-3 text-3xl font-semibold tracking-[-0.03em] text-surface-900">Sign in to select an organization</h1>
        <p class="mt-3 text-sm leading-6 text-surface-600">
          The console uses your OpenKey session. After sign-in you can create an organization with the recommended broker DID from your current account key, or open the advanced broker path.
        </p>
        <div class="mt-6 flex flex-wrap justify-center gap-2">
          <Button href={`/auth/login?redirect=${encodeURIComponent('/console')}`}>Sign in</Button>
          <Button variant="secondary" href="/dashboard">Open account</Button>
        </div>
      </Card>
    </div>
  {:else}
    <div class="grid gap-6 lg:grid-cols-[0.95fr_1.05fr]">
      <section class="space-y-6">
        <Card>
          <div class="flex flex-wrap items-center gap-2">
            <span class="rounded-full border border-primary-200 bg-primary-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-primary-700">
              OpenKey Console
            </span>
            <span class="rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] text-surface-600">
              Session-authenticated
            </span>
          </div>
          <h1 class="mt-4 text-4xl font-semibold tracking-[-0.04em] text-surface-900 text-balance">
            Select or create an organization
          </h1>
          <p class="mt-4 max-w-2xl text-sm leading-6 text-surface-600">
            Each organization owns its apps, credentials, managed accounts, and webhook state. Start with the recommended broker DID from your current OpenKey key, then switch to the advanced DID path only if you need to bring your own broker identity.
          </p>

          <div class="mt-6 grid gap-3 sm:grid-cols-3">
            <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
              <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Organizations</div>
              <div class="mt-2 text-2xl font-semibold text-surface-900">{organizations.length}</div>
            </div>
            <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
              <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Recommended broker</div>
              <div class="mt-2 text-sm font-mono text-surface-900 break-all">
                {#if loadingKeys}
                  Loading key...
                {:else if recommendedBrokerDid}
                  {recommendedBrokerDid}
                {:else}
                  Advanced only
                {/if}
              </div>
            </div>
            <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
              <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Current plan</div>
              <div class="mt-2 text-sm font-semibold text-surface-900">Free, Pro, or Enterprise</div>
            </div>
          </div>
        </Card>

        <Card>
          <div class="flex items-start justify-between gap-4">
            <div>
              <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Create an organization</h2>
              <p class="mt-1 text-sm leading-6 text-surface-600">
                The recommended path uses your current OpenKey key as the broker DID. The manual broker DID field stays available under the advanced toggle and in the legacy organization page.
              </p>
            </div>
            <span class="rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-semibold text-surface-600">Free plan</span>
          </div>

          <form class="mt-6 space-y-5" onsubmit={(event) => { event.preventDefault(); void createOrganization(); }}>
            <div class="space-y-2">
              <label for="organization-name" class="text-sm font-semibold text-surface-900">Organization name</label>
              <Input id="organization-name" bind:value={organizationName} placeholder="OpenKey Labs" required />
            </div>

            <div class="space-y-2">
              <div class="flex items-center justify-between gap-3">
                <label for="broker-did" class="text-sm font-semibold text-surface-900">Broker DID</label>
                <button
                  type="button"
                  class="text-xs font-semibold text-primary-600 underline-offset-4 hover:underline"
                  onclick={() => selectBrokerDidMode(!useAdvancedBrokerDid)}
                >
                  {useAdvancedBrokerDid ? 'Use recommended DID' : 'Use advanced DID'}
                </button>
              </div>
              {#if useAdvancedBrokerDid}
                <Input
                  id="broker-did"
                  bind:value={manualBrokerDid}
                  placeholder="did:key:z..."
                  autocomplete="off"
                  spellcheck="false"
                  required
                />
              {:else}
                <div class="rounded-2xl border border-surface-200 bg-surface-50 px-3 py-3">
                  {#if recommendedBrokerDid}
                    <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Recommended from your current OpenKey key</div>
                    <div class="mt-2 break-all font-mono text-sm text-surface-900">{recommendedBrokerDid}</div>
                  {:else}
                    <div class="text-sm text-surface-600">
                      No personal key was available. Switch to the advanced broker DID path to continue.
                    </div>
                  {/if}
                </div>
              {/if}
              <p class="text-xs leading-5 text-surface-500">
                The broker DID receives tenant-parent delegations for this organization. It should be a real, controlled DID, not a placeholder.
              </p>
            </div>

            <div class="flex flex-wrap gap-2">
              <Button type="submit" disabled={creating || (!recommendedBrokerDid && !useAdvancedBrokerDid)}>
                {creating ? 'Creating...' : 'Create organization'}
              </Button>
              <Button variant="secondary" href="/dashboard/organizations">Advanced legacy flow</Button>
            </div>
          </form>
        </Card>

        {#if error}
          <Card class="border-red-200 bg-red-50/60">
            <p class="text-sm font-medium text-red-700">{error}</p>
          </Card>
        {/if}
      </section>

      <section class="space-y-4">
        <div class="flex items-end justify-between gap-4">
          <div>
            <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Your organizations</h2>
            <p class="mt-1 text-sm leading-6 text-surface-600">Open an existing tenant console or review the plan and role at a glance.</p>
          </div>
        </div>

        {#if organizations.length === 0 && !loading}
          <Card class="space-y-3">
            <h3 class="text-base font-semibold text-surface-900">No organizations yet</h3>
            <p class="text-sm leading-6 text-surface-600">
              Create the first organization to begin managing apps, credentials, managed accounts, and webhooks.
            </p>
          </Card>
        {:else}
          <div class="grid gap-3">
            {#each organizations as organization}
              <Card class="space-y-4">
                <div class="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 class="text-base font-semibold text-surface-900">{organization.name}</h3>
                    <p class="mt-1 text-xs font-mono text-surface-500 break-all">{organization.brokerDid ?? 'No broker DID configured'}</p>
                  </div>
                  <div class="flex flex-wrap gap-2">
                    <span class="rounded-full border border-surface-200 bg-surface-50 px-2.5 py-1 text-xs font-semibold text-surface-600">{organization.role}</span>
                    <span class="rounded-full border border-primary-200 bg-primary-50 px-2.5 py-1 text-xs font-semibold text-primary-700">{organization.plan}</span>
                  </div>
                </div>

                <dl class="grid gap-3 text-sm sm:grid-cols-3">
                  <div>
                    <dt class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Apps</dt>
                    <dd class="mt-1 font-semibold text-surface-900">{organization.usage.apps}</dd>
                  </div>
                  <div>
                    <dt class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Managed accounts</dt>
                    <dd class="mt-1 font-semibold text-surface-900">{organization.usage.managedAccounts}</dd>
                  </div>
                  <div>
                    <dt class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Members</dt>
                    <dd class="mt-1 font-semibold text-surface-900">{organization.usage.members}</dd>
                  </div>
                </dl>

                <div class="flex flex-wrap gap-2">
                  <Button href={`/console/${organization.id}`}>Open console</Button>
                  <Button variant="secondary" href={`/console/${organization.id}/apps`}>Apps</Button>
                </div>
              </Card>
            {/each}
          </div>
        {/if}
      </section>
    </div>
  {/if}
</div>
