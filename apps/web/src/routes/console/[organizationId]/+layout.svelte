<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type ConsoleOverview, type OrganizationSummary } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import { CONSOLE_SHELL, type ConsoleShellContext } from '$lib/console-shell';
  import { setContext, tick } from 'svelte';
  import { writable, type Writable } from 'svelte/store';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();

  const session = authClient.useSession();

  const organizations = writable<OrganizationSummary[]>([]);
  const overview = writable<ConsoleOverview | null>(null);
  const loading = writable(true);
  const error = writable('');
  const mobileOpen = writable(false);

  let currentOrganizationId = $derived($page.params.organizationId ?? '');
  let loadState = $state<'loading' | 'ready' | 'unauthenticated' | 'not-found' | 'error'>('loading');
  let loadedFor = $state('');
  let mobileDrawer = $state<HTMLElement | null>(null);
  let mobileCloseButton = $state<HTMLButtonElement | null>(null);
  let lastFocusedElement: HTMLElement | null = null;

  const navItems = [
    { href: '', label: 'Overview' },
    { href: '/apps', label: 'Apps' },
    { href: '/credentials', label: 'Credentials' },
    { href: '/managed-accounts', label: 'Managed accounts' },
    { href: '/webhooks', label: 'Webhooks' },
  ] as const;

  async function refresh() {
    const organizationId = currentOrganizationId;
    if (!organizationId) return;

    loading.set(true);
    error.set('');

    try {
      const [organizationResult, overviewResult] = await Promise.all([
        api.listConsoleOrganizations(),
        api.getConsoleOverview(organizationId),
      ]);
      organizations.set(organizationResult.organizations);
      overview.set(overviewResult);
      loadState = 'ready';
      loadedFor = organizationId;
    } catch (caught: any) {
      const status = caught?.status;
      const message = typeof caught?.message === 'string' ? caught.message : 'Failed to load the console.';
      if (status === 401) {
        loadState = 'unauthenticated';
      } else if (status === 404) {
        loadState = 'not-found';
      } else {
        loadState = 'error';
        error.set(message);
      }
      overview.set(null);
    } finally {
      loading.set(false);
    }
  }

  const shell: ConsoleShellContext = {
    organizations,
    overview,
    loading,
    error,
    mobileOpen,
    refresh,
  };

  setContext(CONSOLE_SHELL, shell);

  $effect(() => {
    const organizationId = currentOrganizationId;
    if ($session.isPending) return;
    if (!$session.data) {
      loadState = 'unauthenticated';
      loading.set(false);
      return;
    }
    if (organizationId && loadedFor !== organizationId) {
      void refresh();
    }
  });

  $effect(() => {
    if ($mobileOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  });

  function closeMobileNav() {
    mobileOpen.set(false);
  }

  function openMobileNav(trigger: HTMLElement | null) {
    lastFocusedElement = trigger ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    mobileOpen.set(true);
  }

  function navigate(nextPath: string) {
    closeMobileNav();
    void goto(nextPath);
  }

  function organizationLabel(id: string) {
    return $organizations.find((organization) => organization.id === id)?.name ?? 'Select organization';
  }

  function focusableElements(container: HTMLElement): HTMLElement[] {
    return Array.from(
      container.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ),
    ).filter((element) => !element.hasAttribute('disabled') && element.tabIndex >= 0);
  }

  function handleDrawerKeydown(event: KeyboardEvent) {
    if (!$mobileOpen || !mobileDrawer) return;

    if (event.key === 'Escape') {
      event.preventDefault();
      closeMobileNav();
      return;
    }
    if (event.key !== 'Tab') return;

    const focusables = focusableElements(mobileDrawer);
    if (focusables.length === 0) {
      event.preventDefault();
      mobileDrawer?.focus({ preventScroll: true });
      return;
    }

    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active = document.activeElement;
    if (event.shiftKey && active === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  }

  $effect(() => {
    if ($mobileOpen) {
      document.body.style.overflow = 'hidden';
      void tick().then(() => {
        mobileCloseButton?.focus({ preventScroll: true });
        mobileDrawer?.focus({ preventScroll: true });
      });
    } else {
      document.body.style.overflow = '';
      const restore = lastFocusedElement;
      lastFocusedElement = null;
      void tick().then(() => {
        restore?.focus({ preventScroll: true });
      });
    }

    return () => {
      document.body.style.overflow = '';
    };
  });
</script>

<svelte:window onkeydown={handleDrawerKeydown} />

{#if loadState === 'loading'}
  <div class="min-h-[100vh] px-4 py-6 sm:px-6 lg:px-8">
    <div class="mx-auto max-w-7xl">
      <Card class="space-y-4">
        <div class="h-4 w-40 rounded-full bg-surface-100"></div>
        <div class="h-10 w-2/3 rounded-2xl bg-surface-100"></div>
        <div class="grid gap-4 lg:grid-cols-[280px_minmax(0,1fr)]">
          <div class="space-y-3 rounded-2xl border border-surface-100 bg-surface-50 p-4">
            <div class="h-4 w-24 rounded-full bg-surface-100"></div>
            <div class="h-10 rounded-2xl bg-surface-100"></div>
            <div class="h-10 rounded-2xl bg-surface-100"></div>
            <div class="h-10 rounded-2xl bg-surface-100"></div>
          </div>
          <div class="space-y-4 rounded-2xl border border-surface-100 bg-surface-50 p-4">
            <div class="h-5 w-56 rounded-full bg-surface-100"></div>
            <div class="h-28 rounded-2xl bg-surface-100"></div>
            <div class="h-40 rounded-2xl bg-surface-100"></div>
          </div>
        </div>
      </Card>
    </div>
  </div>
{:else if loadState === 'unauthenticated'}
  <div class="mx-auto flex min-h-[100vh] max-w-lg items-center px-4 py-8">
    <Card class="w-full text-center">
      <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">OpenKey Console</p>
      <h1 class="mt-3 text-3xl font-semibold tracking-[-0.03em] text-surface-900">Sign in to continue</h1>
      <p class="mt-3 text-sm leading-6 text-surface-600">
        The organization console uses your OpenKey session. Sign in, then return to the console route you requested.
      </p>
      <div class="mt-6 flex flex-wrap justify-center gap-2">
        <Button href={`/auth/login?redirect=${encodeURIComponent($page.url.pathname + $page.url.search)}`}>Sign in</Button>
        <Button variant="secondary" href="/console">Back to console index</Button>
      </div>
    </Card>
  </div>
{:else if loadState === 'not-found'}
  <div class="mx-auto flex min-h-[100vh] max-w-lg items-center px-4 py-8">
    <Card class="w-full text-center">
      <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">OpenKey Console</p>
      <h1 class="mt-3 text-3xl font-semibold tracking-[-0.03em] text-surface-900">Organization not found</h1>
      <p class="mt-3 text-sm leading-6 text-surface-600">
        This organization either does not exist or is not available to the current OpenKey session. Check the organization selector or return to the console entry page.
      </p>
      <div class="mt-6 flex flex-wrap justify-center gap-2">
        <Button href="/console">Console index</Button>
        <Button variant="secondary" href="/dashboard">Open account</Button>
      </div>
    </Card>
  </div>
{:else if loadState === 'error'}
  <div class="mx-auto flex min-h-[100vh] max-w-lg items-center px-4 py-8">
    <Card class="w-full text-center">
      <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">OpenKey Console</p>
      <h1 class="mt-3 text-3xl font-semibold tracking-[-0.03em] text-surface-900">Console load failed</h1>
      <p class="mt-3 text-sm leading-6 text-surface-600">{ $error || 'The console could not load the current organization.' }</p>
      <div class="mt-6 flex flex-wrap justify-center gap-2">
        <Button onclick={() => void refresh()}>Retry</Button>
        <Button variant="secondary" href="/console">Console index</Button>
      </div>
    </Card>
  </div>
{:else}
  <div class="min-h-[100vh]">
    <div inert={$mobileOpen} aria-hidden={$mobileOpen}>
    <header class="sticky top-0 z-20 border-b border-surface-200/80 bg-surface-50/92 backdrop-blur">
      <div class="mx-auto flex max-w-7xl items-center justify-between gap-3 px-4 py-3 sm:px-6 lg:px-8">
        <div class="flex min-w-0 items-center gap-3">
          <button
            type="button"
            class="inline-flex h-10 w-10 items-center justify-center rounded-full border border-surface-200 bg-white text-surface-700 transition-colors hover:border-primary-300 hover:text-primary-700 lg:hidden"
            aria-label="Open console navigation"
            aria-expanded={$mobileOpen}
            aria-controls="console-drawer"
            onclick={(event) => openMobileNav(event.currentTarget as HTMLButtonElement)}
          >
            <span class="text-lg">☰</span>
          </button>
          <div class="min-w-0">
            <p class="text-[11px] font-semibold uppercase tracking-[0.12em] text-surface-500">OpenKey Console</p>
            <h1 class="truncate text-base font-semibold tracking-[-0.03em] text-surface-900">
              {($overview?.organization.name) || organizationLabel(currentOrganizationId)}
            </h1>
          </div>
        </div>

        <div class="flex min-w-0 items-center gap-2">
          <span class="hidden rounded-full border border-surface-200 bg-white px-3 py-1.5 text-xs font-semibold text-surface-600 sm:inline-flex">
            {$overview?.organization.role ?? 'MEMBER'}
          </span>
          <label class="sr-only" for="organization-switcher">Switch organization</label>
          <select
            id="organization-switcher"
            class="hidden h-10 rounded-full border border-surface-200 bg-white px-3 text-sm text-surface-900 outline-none transition-colors hover:border-primary-300 focus-visible:border-primary-500 focus-visible:ring-2 focus-visible:ring-primary-200 sm:block"
            onchange={(event) => {
              const next = (event.currentTarget as HTMLSelectElement).value;
              navigate(`/console/${next}`);
            }}
            value={currentOrganizationId}
          >
            {#each $organizations as organization}
              <option value={organization.id}>{organization.name}</option>
            {/each}
          </select>
        </div>
      </div>
    </header>

    <div class="mx-auto grid max-w-7xl gap-6 px-4 py-6 sm:px-6 lg:grid-cols-[300px_minmax(0,1fr)] lg:px-8">
      <aside class="hidden lg:block">
        <div class="sticky top-[88px] space-y-4">
          <Card class="space-y-4">
            <div class="flex items-start justify-between gap-3">
              <div>
                <p class="text-xs font-semibold uppercase tracking-[0.12em] text-surface-500">Organization</p>
                <h2 class="mt-1 text-lg font-semibold tracking-[-0.03em] text-surface-900">{($overview?.organization.name) || organizationLabel(currentOrganizationId)}</h2>
              </div>
              <span class="rounded-full border border-primary-200 bg-primary-50 px-3 py-1 text-xs font-semibold text-primary-700">
                {$overview?.organization.plan ?? 'FREE'}
              </span>
            </div>
            <div class="rounded-2xl border border-surface-200 bg-surface-50 p-3">
              <label class="sr-only" for="sidebar-switcher">Switch organization</label>
              <select
                id="sidebar-switcher"
                class="h-10 w-full rounded-full border border-surface-200 bg-white px-3 text-sm text-surface-900 outline-none focus-visible:border-primary-500 focus-visible:ring-2 focus-visible:ring-primary-200"
                onchange={(event) => {
                  const next = (event.currentTarget as HTMLSelectElement).value;
                  navigate(`/console/${next}`);
                }}
                value={currentOrganizationId}
              >
                {#each $organizations as organization}
                  <option value={organization.id}>{organization.name}</option>
                {/each}
              </select>
            </div>
            <div class="grid gap-3 text-sm">
              <div class="flex items-center justify-between gap-3 border-b border-dotted border-surface-200 pb-2">
                <span class="text-surface-500">Role</span>
                <span class="font-semibold text-surface-900">{$overview?.organization.role ?? 'MEMBER'}</span>
              </div>
              <div class="flex items-center justify-between gap-3 border-b border-dotted border-surface-200 pb-2">
                <span class="text-surface-500">Billing</span>
                <span class="font-semibold text-surface-900">{$overview?.organization.billingState ?? 'FREE'}</span>
              </div>
              <div class="flex items-center justify-between gap-3">
                <span class="text-surface-500">Broker DID</span>
                <span class="max-w-[170px] truncate font-mono text-xs text-surface-700" title={$overview?.organization.brokerDid ?? ''}>
                  {$overview?.organization.brokerDid ?? 'Not configured'}
                </span>
              </div>
            </div>
          </Card>

          <Card class="space-y-2">
            <p class="text-xs font-semibold uppercase tracking-[0.12em] text-surface-500">Navigation</p>
            <nav class="space-y-1" aria-label="Console sections">
              {#each navItems as item}
                <a
                  href={item.href ? `/console/${$page.params.organizationId}${item.href}` : `/console/${$page.params.organizationId}`}
                  class={`flex items-center justify-between rounded-full border px-3 py-2 text-sm no-underline transition-colors ${
                    $page.url.pathname === `/console/${$page.params.organizationId}${item.href}`
                      ? 'border-primary-200 bg-primary-50 text-primary-700'
                      : 'border-transparent text-surface-600 hover:border-surface-200 hover:bg-surface-50 hover:text-surface-900'
                  }`}
                  aria-current={$page.url.pathname === `/console/${$page.params.organizationId}${item.href}` ? 'page' : undefined}
                >
                  <span>{item.label}</span>
                </a>
              {/each}
            </nav>
          </Card>

          <Card class="space-y-3">
            <p class="text-xs font-semibold uppercase tracking-[0.12em] text-surface-500">Console note</p>
            <p class="text-sm leading-6 text-surface-600">
              Members can read the console, but admin-only actions stay hidden in the section pages. One-time secrets are never persisted in the browser.
            </p>
            <div class="rounded-2xl border border-surface-200 bg-surface-50 px-3 py-3 text-xs leading-5 text-surface-600">
              The user-owned eject path lives in the personal <a class="font-semibold text-primary-700 underline-offset-4 hover:underline" href="/dashboard/managed-accounts">OpenKey Account</a>.
            </div>
          </Card>
        </div>
      </aside>

      <main class="min-w-0">
        <div class="space-y-6">
          {@render children()}
        </div>
      </main>
    </div>

    {#if $mobileOpen}
      <div class="fixed inset-0 z-30 lg:hidden">
        <button
          type="button"
          class="absolute inset-0 border-0 bg-surface-900/30 p-0 text-left"
          aria-label="Close console navigation"
          onclick={closeMobileNav}
        ></button>
        <div
          id="console-drawer"
          bind:this={mobileDrawer}
          role="dialog"
          tabindex="-1"
          aria-modal="true"
          aria-labelledby="console-drawer-title"
          class="absolute left-0 top-0 z-10 h-full w-[88vw] max-w-sm border-r border-surface-200 bg-surface-50 p-4 shadow-2xl"
        >
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-[11px] font-semibold uppercase tracking-[0.12em] text-surface-500">OpenKey Console</p>
              <h2 id="console-drawer-title" class="text-base font-semibold tracking-[-0.03em] text-surface-900">{($overview?.organization.name) || organizationLabel(currentOrganizationId)}</h2>
            </div>
            <button
              type="button"
              bind:this={mobileCloseButton}
              class="inline-flex h-10 w-10 items-center justify-center rounded-full border border-surface-200 bg-white text-surface-700"
              aria-label="Close console navigation"
              onclick={closeMobileNav}
            >
              ×
            </button>
          </div>

          <div class="mt-4 space-y-4">
            <div class="rounded-2xl border border-surface-200 bg-white p-3">
              <label class="sr-only" for="mobile-switcher">Switch organization</label>
              <select
                id="mobile-switcher"
                class="h-10 w-full rounded-full border border-surface-200 bg-white px-3 text-sm text-surface-900"
                onchange={(event) => {
                  const next = (event.currentTarget as HTMLSelectElement).value;
                  navigate(`/console/${next}`);
                }}
                value={currentOrganizationId}
              >
                {#each $organizations as organization}
                  <option value={organization.id}>{organization.name}</option>
                {/each}
              </select>
            </div>

            <nav class="space-y-1" aria-label="Console sections">
              {#each navItems as item}
                <a
                  href={item.href ? `/console/${$page.params.organizationId}${item.href}` : `/console/${$page.params.organizationId}`}
                  onclick={() => closeMobileNav()}
                  class={`flex items-center justify-between rounded-full border px-3 py-2 text-sm no-underline transition-colors ${
                    $page.url.pathname === `/console/${$page.params.organizationId}${item.href}`
                      ? 'border-primary-200 bg-primary-50 text-primary-700'
                      : 'border-transparent text-surface-600 hover:border-surface-200 hover:bg-surface-50 hover:text-surface-900'
                  }`}
                >
                  <span>{item.label}</span>
                </a>
              {/each}
            </nav>
          </div>
        </div>
      </div>
    {/if}
  </div>
  </div>
{/if}
