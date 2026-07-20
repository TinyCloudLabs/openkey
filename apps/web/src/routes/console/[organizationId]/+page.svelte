<script lang="ts">
  import { getContext } from 'svelte';
  import { CONSOLE_SHELL, type ConsoleShellContext } from '$lib/console-shell';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  const { overview, refresh } = getContext<ConsoleShellContext>(CONSOLE_SHELL);

  function humanBytes(value: string): string {
    const bytes = BigInt(value);
    const units = [
      { threshold: 1_000_000_000_000n, label: 'TB' },
      { threshold: 1_000_000_000n, label: 'GB' },
      { threshold: 1_000_000n, label: 'MB' },
      { threshold: 1_000n, label: 'KB' },
    ] as const;
    for (const unit of units) {
      if (bytes >= unit.threshold) {
        const value = Number(bytes / unit.threshold);
        return `${value} ${unit.label}`;
      }
    }
    return `${bytes.toString()} bytes`;
  }

  function formatCount(value: number, max: number, enforced: boolean): string {
    return enforced ? `${value} / ${max}` : `${value} of ${max}`;
  }

  function checklistItems() {
    const data = $overview;
    if (!data) return [];
    const orgId = data.organization.id;
    return [
      {
        title: 'Confirm the organization shell',
        done: true,
        description: `${data.organization.name} is open in the console.`,
        href: `/console/${orgId}`,
      },
      {
        title: 'Create the first app',
        done: data.usage.apps > 0,
        description: data.usage.apps > 0
          ? `${data.usage.apps} app${data.usage.apps === 1 ? '' : 's'} are already registered.`
          : 'Create a browser or native app with strict redirect rules.',
        href: `/console/${orgId}/apps`,
      },
      {
        title: 'Issue a server credential',
        done: data.usage.credentials > 0,
        description: data.usage.credentials > 0
          ? `${data.usage.credentials} credential${data.usage.credentials === 1 ? '' : 's'} exist.`
          : 'Create the one-time secret that bootstraps tenant registration.',
        href: `/console/${orgId}/credentials`,
      },
      {
        title: 'Register the first managed account',
        done: data.usage.managedAccounts > 0,
        description: data.usage.managedAccounts > 0
          ? `${data.usage.managedAccounts} managed account${data.usage.managedAccounts === 1 ? '' : 's'} are active.`
          : 'Use a tenant app to register the first managed account, then inspect its lifecycle.',
        href: `/console/${orgId}/managed-accounts`,
      },
      {
        title: 'Add an optional webhook',
        done: data.usage.webhookEndpoints > 0,
        description: data.usage.webhookEndpoints > 0
          ? `${data.usage.webhookEndpoints} webhook endpoint${data.usage.webhookEndpoints === 1 ? '' : 's'} are configured.`
          : 'Wire lifecycle events only if your integration needs delivery history.',
        href: `/console/${orgId}/webhooks`,
      },
    ];
  }
</script>

<svelte:head>
  <title>{($overview?.organization.name ?? 'Console')} · OpenKey Console</title>
</svelte:head>

{#if !$overview}
  <Card>
    <p class="text-sm text-surface-600">Loading overview…</p>
  </Card>
{:else}
  <div class="space-y-6">
    <Card class="space-y-5">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">Overview</p>
          <h1 class="mt-2 text-3xl font-semibold tracking-[-0.04em] text-surface-900 text-balance">
            { $overview.organization.name }
          </h1>
          <p class="mt-3 max-w-2xl text-sm leading-6 text-surface-600">
            This surface shows the real organizational state. Use it to understand what is configured, what is enforced today, and what remains on the activation path.
          </p>
        </div>
        <div class="flex flex-wrap gap-2">
          <span class="rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-semibold text-surface-600">{$overview.organization.role}</span>
          <span class="rounded-full border border-primary-200 bg-primary-50 px-3 py-1 text-xs font-semibold text-primary-700">{$overview.organization.plan}</span>
          <span class="rounded-full border border-surface-200 bg-white px-3 py-1 text-xs font-semibold text-surface-600">{$overview.organization.billingState}</span>
        </div>
      </div>

      <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
          <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Apps</div>
          <div class="mt-2 text-2xl font-semibold text-surface-900">{formatCount($overview.usage.apps, $overview.entitlements?.maxApps ?? $overview.usage.apps, true)}</div>
          <div class="mt-1 text-xs text-surface-500">Currently enforced on create.</div>
        </div>
        <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
          <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Managed accounts</div>
          <div class="mt-2 text-2xl font-semibold text-surface-900">{formatCount($overview.usage.managedAccounts, $overview.entitlements?.maxManagedAccounts ?? $overview.usage.managedAccounts, false)}</div>
          <div class="mt-1 text-xs text-surface-500">Configured ceiling in the plan record.</div>
        </div>
        <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
          <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Members</div>
          <div class="mt-2 text-2xl font-semibold text-surface-900">{formatCount($overview.usage.members, $overview.entitlements?.maxOrganizationMembers ?? $overview.usage.members, false)}</div>
          <div class="mt-1 text-xs text-surface-500">Configured ceiling only.</div>
        </div>
        <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
          <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Webhook endpoints</div>
          <div class="mt-2 text-2xl font-semibold text-surface-900">{formatCount($overview.usage.webhookEndpoints, $overview.entitlements?.maxWebhookEndpoints ?? $overview.usage.webhookEndpoints, true)}</div>
          <div class="mt-1 text-xs text-surface-500">Currently enforced on create.</div>
        </div>
      </div>
    </Card>

    <div class="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
      <Card class="space-y-4">
        <div class="flex items-center justify-between gap-3">
          <div>
            <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Configured entitlements</h2>
            <p class="mt-1 text-sm leading-6 text-surface-600">
              These values describe the active plan contract. Only some of them are enforced live today.
            </p>
          </div>
          <Button variant="secondary" onclick={() => void refresh()}>Refresh</Button>
        </div>

        <div class="grid gap-3 md:grid-cols-2">
          <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
            <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Requests per minute</div>
            <div class="mt-2 text-lg font-semibold text-surface-900">{$overview.entitlements?.requestsPerMinute ?? 'N/A'}</div>
            <div class="mt-1 text-xs text-surface-500">Configured ceiling.</div>
          </div>
          <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
            <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Monthly active managed users</div>
            <div class="mt-2 text-lg font-semibold text-surface-900">{$overview.entitlements?.monthlyActiveManagedUsers ?? 'N/A'}</div>
            <div class="mt-1 text-xs text-surface-500">Configured ceiling.</div>
          </div>
          <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
            <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Delegation TTL</div>
            <div class="mt-2 text-lg font-semibold text-surface-900">{$overview.entitlements ? `${Math.round($overview.entitlements.maxTenantDelegationTtlSeconds / 3600)}h` : 'N/A'}</div>
            <div class="mt-1 text-xs text-surface-500">Configured ceiling.</div>
          </div>
          <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
            <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Audit retention</div>
            <div class="mt-2 text-lg font-semibold text-surface-900">{$overview.entitlements?.auditRetentionDays ?? 'N/A'} days</div>
            <div class="mt-1 text-xs text-surface-500">Configured ceiling.</div>
          </div>
          <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
            <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Storage per managed account</div>
            <div class="mt-2 text-lg font-semibold text-surface-900">{humanBytes($overview.entitlements?.storageBytesPerManagedAccount ?? '0')}</div>
            <div class="mt-1 text-xs text-surface-500">Configured ceiling.</div>
          </div>
          <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
            <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Policy version ceiling</div>
            <div class="mt-2 text-lg font-semibold text-surface-900">{$overview.entitlements?.maxTenantPolicyVersion ?? 'N/A'}</div>
            <div class="mt-1 text-xs text-surface-500">Configured ceiling.</div>
          </div>
        </div>

        <div class="rounded-2xl border border-dotted border-surface-200 bg-white px-4 py-3 text-sm leading-6 text-surface-600">
          App creation and webhook endpoint creation are enforced against plan ceilings today. Member count, managed-user volume, request rate, and audit retention are surfaced here as configured contract values so operators can see the plan without confusing it with checkout.
        </div>
      </Card>

      <Card class="space-y-4">
        <div>
          <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Activation checklist</h2>
          <p class="mt-1 text-sm leading-6 text-surface-600">
            Resume where you left off. Each step is derived from the actual resource state.
          </p>
        </div>

        <div class="space-y-3">
          {#each checklistItems() as item}
            <a
              href={item.href}
              class={`block rounded-2xl border p-4 no-underline transition-colors ${
                item.done ? 'border-surface-200 bg-surface-50' : 'border-primary-200 bg-primary-50/60'
              }`}
            >
              <div class="flex items-start justify-between gap-3">
                <div class="min-w-0">
                  <div class="flex items-center gap-2">
                    <span class={`inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] font-bold ${item.done ? 'bg-primary-600 text-white' : 'border border-primary-400 text-primary-700'}`}>
                      {item.done ? '✓' : '•'}
                    </span>
                    <span class="font-semibold text-surface-900">{item.title}</span>
                  </div>
                  <p class="mt-2 text-sm leading-6 text-surface-600">{item.description}</p>
                </div>
                <span class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-400">
                  {item.done ? 'Done' : 'Next'}
                </span>
              </div>
            </a>
          {/each}
        </div>

        <div class="rounded-2xl border border-surface-200 bg-surface-50 px-4 py-3 text-sm leading-6 text-surface-600">
          If you are a member, you can still read this overview. Mutation controls remain hidden on the underlying pages.
        </div>
      </Card>
    </div>

    <Card class="space-y-3">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Broker and plan notes</h2>
          <p class="mt-1 text-sm leading-6 text-surface-600">
            The broker DID is configured on the organization and the plan is shown without inventing pricing or checkout behavior.
          </p>
        </div>
        <div class="flex flex-wrap gap-2">
          <Button variant="secondary" href={`/console/${$overview.organization.id}/apps`}>Manage apps</Button>
          <Button href={`/console/${$overview.organization.id}/credentials`}>Issue credential</Button>
        </div>
      </div>

      <dl class="grid gap-3 md:grid-cols-2">
        <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
          <dt class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Broker DID</dt>
          <dd class="mt-2 break-all font-mono text-sm text-surface-900">{ $overview.organization.brokerDid ?? 'Not configured' }</dd>
        </div>
        <div class="rounded-2xl border border-surface-200 bg-surface-50 p-4">
          <dt class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Plan status</dt>
          <dd class="mt-2 text-sm font-semibold text-surface-900">{ $overview.organization.plan } plan, { $overview.organization.billingState } billing</dd>
        </div>
      </dl>
    </Card>
  </div>
{/if}
