<script lang="ts">
  import { getContext } from 'svelte';
  import { page } from '$app/stores';
  import { CONSOLE_SHELL, type ConsoleShellContext } from '$lib/console-shell';
  import {
    validateConsoleMetadataUrl,
    validateConsoleRedirectUris,
  } from '$lib/console-validation';
  import { api, type ConsoleApp } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  const { overview, refresh } = getContext<ConsoleShellContext>(CONSOLE_SHELL);
  let currentOrganizationId = $derived($page.params.organizationId ?? '');

  let apps = $state<ConsoleApp[]>([]);
  let loading = $state(true);
  let error = $state('');
  let createError = $state('');
  let createLoading = $state(false);
  let editingAppId = $state<string | null>(null);
  let editError = $state('');
  let editLoading = $state(false);

  let newName = $state('');
  let newType = $state<'spa' | 'native'>('spa');
  let newRedirectUris = $state('');
  let newUri = $state('');
  let newIcon = $state('');

  let editName = $state('');
  let editType = $state<'spa' | 'native'>('spa');
  let editRedirectUris = $state('');
  let editUri = $state('');
  let editIcon = $state('');
  let editDisabled = $state(false);

  let loadedFor = $state('');

  function normalizeLines(value: string) {
    return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  }

  function validateOptionalMetadataUrl(value: string) {
    return value.trim() ? validateConsoleMetadataUrl(value) : { valid: true } as const;
  }

  async function loadApps() {
    loading = true;
    error = '';
    try {
      const result = await api.listConsoleApps(currentOrganizationId);
      apps = result.apps;
    } catch (caught: any) {
      error = caught.message || 'Could not load apps.';
    } finally {
      loading = false;
    }
  }

  function beginCreate() {
    createError = '';
    newName = '';
    newType = 'spa';
    newRedirectUris = 'https://example.com/callback';
    newUri = '';
    newIcon = '';
  }

  function beginEdit(app: ConsoleApp) {
    editingAppId = app.id;
    editError = '';
    editName = app.name;
    editType = app.type;
    editRedirectUris = app.redirectUris.join('\n');
    editUri = app.uri ?? '';
    editIcon = app.icon ?? '';
    editDisabled = app.disabled;
  }

  function cancelEdit() {
    editingAppId = null;
    editError = '';
  }

  async function createApp() {
    createLoading = true;
    createError = '';
    const redirectUris = normalizeLines(newRedirectUris);
    const redirectResult = validateConsoleRedirectUris(redirectUris, newType);
    const metadataResult = validateOptionalMetadataUrl(newUri);
    const iconResult = validateOptionalMetadataUrl(newIcon);
    if (!newName.trim()) createError = 'Enter an app name.';
    else if (!redirectResult.valid) createError = redirectResult.reason;
    else if (!metadataResult.valid) createError = metadataResult.reason;
    else if (!iconResult.valid) createError = iconResult.reason;
    else {
      try {
        await api.createConsoleApp(currentOrganizationId, {
          name: newName.trim(),
          type: newType,
          redirectUris,
          uri: newUri.trim() || null,
          icon: newIcon.trim() || null,
        });
        beginCreate();
        await Promise.all([loadApps(), refresh()]);
      } catch (caught: any) {
        createError = caught.message || 'Could not create the app.';
      }
    }
    createLoading = false;
  }

  async function saveEdit(app: ConsoleApp) {
    editLoading = true;
    editError = '';
    const redirectUris = normalizeLines(editRedirectUris);
    const redirectResult = validateConsoleRedirectUris(redirectUris, editType);
    const metadataResult = validateOptionalMetadataUrl(editUri);
    const iconResult = validateOptionalMetadataUrl(editIcon);
    if (!editName.trim()) editError = 'Enter an app name.';
    else if (!redirectResult.valid) editError = redirectResult.reason;
    else if (!metadataResult.valid) editError = metadataResult.reason;
    else if (!iconResult.valid) editError = iconResult.reason;
    else {
      try {
        await api.updateConsoleApp(currentOrganizationId, app.id, {
          name: editName.trim(),
          type: editType,
          redirectUris,
          uri: editUri.trim() || null,
          icon: editIcon.trim() || null,
          disabled: editDisabled,
        });
        cancelEdit();
        await Promise.all([loadApps(), refresh()]);
      } catch (caught: any) {
        editError = caught.message || 'Could not save the app.';
      }
    }
    editLoading = false;
  }

  $effect(() => {
    const orgId = currentOrganizationId;
    if (loadedFor !== orgId) {
      loadedFor = orgId;
      void loadApps();
      beginCreate();
    }
  });
</script>

<svelte:head>
  <title>Apps · OpenKey Console</title>
</svelte:head>

<div class="space-y-6">
  <Card class="space-y-4">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">Connected apps</p>
        <h1 class="mt-2 text-3xl font-semibold tracking-[-0.04em] text-surface-900">Apps with strict redirect rules</h1>
        <p class="mt-3 max-w-2xl text-sm leading-6 text-surface-600">
          Browser apps must use HTTPS or loopback HTTP. Native apps may use private-use schemes. Metadata URLs are limited to non-credentialed HTTP(S) origins.
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <span class="rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-semibold text-surface-600">
          { $overview?.usage.apps ?? apps.length } apps
        </span>
        <span class="rounded-full border border-primary-200 bg-primary-50 px-3 py-1 text-xs font-semibold text-primary-700">
          { $overview?.entitlements?.maxApps ?? 'N/A' } max
        </span>
      </div>
    </div>

    <div class="rounded-2xl border border-dotted border-surface-200 bg-white px-4 py-3 text-sm leading-6 text-surface-600">
      The API enforces app quotas today. Members can read this list, but creation and edits stay hidden unless you are an admin.
    </div>
  </Card>

  {#if error}
    <Card class="border-red-200 bg-red-50/60">
      <p class="text-sm font-medium text-red-700">{error}</p>
    </Card>
  {/if}

  {#if $overview?.organization.role === 'ADMIN'}
    <Card class="space-y-5">
      <div class="flex items-start justify-between gap-4">
        <div>
          <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Create app</h2>
          <p class="mt-1 text-sm leading-6 text-surface-600">
            Use explicit redirect URIs. The console will reject anything that looks like an open redirect, a non-loopback HTTP browser URI, or a credentialed metadata URL.
          </p>
        </div>
        <span class="rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-semibold text-surface-600">
          {$overview && $overview.usage.apps >= ($overview.entitlements?.maxApps ?? $overview.usage.apps) ? 'Quota reached' : 'Admin'}
        </span>
      </div>

      <form class="grid gap-4 lg:grid-cols-2" onsubmit={(event) => { event.preventDefault(); void createApp(); }}>
        <div class="space-y-2">
          <label class="text-sm font-semibold text-surface-900" for="app-name">App name</label>
          <Input id="app-name" bind:value={newName} placeholder="Dashboard for Acme" required />
        </div>
        <div class="space-y-2">
          <label class="text-sm font-semibold text-surface-900" for="app-type">App type</label>
          <select
            id="app-type"
            class="h-10 w-full rounded-xl border border-surface-200 bg-white px-3 text-sm text-surface-900 focus-visible:border-primary-500 focus-visible:ring-2 focus-visible:ring-primary-200"
            bind:value={newType}
          >
            <option value="spa">Browser app</option>
            <option value="native">Native app</option>
          </select>
        </div>
        <div class="space-y-2 lg:col-span-2">
          <label class="text-sm font-semibold text-surface-900" for="redirect-uris">Redirect URIs</label>
          <textarea
            id="redirect-uris"
            bind:value={newRedirectUris}
            rows="4"
            class="w-full rounded-2xl border border-surface-200 bg-white px-3 py-3 text-sm text-surface-900 placeholder:text-surface-400 focus-visible:border-primary-500 focus-visible:ring-2 focus-visible:ring-primary-200"
            placeholder="https://app.example.com/callback"
          ></textarea>
          <p class="text-xs leading-5 text-surface-500">
            One URI per line. Browser apps need HTTPS or loopback HTTP. Native apps may use private-use schemes with a callback path.
          </p>
        </div>
        <div class="space-y-2">
          <label class="text-sm font-semibold text-surface-900" for="app-uri">Metadata URL</label>
          <Input id="app-uri" bind:value={newUri} placeholder="https://app.example.com" />
        </div>
        <div class="space-y-2">
          <label class="text-sm font-semibold text-surface-900" for="app-icon">Icon URL</label>
          <Input id="app-icon" bind:value={newIcon} placeholder="https://app.example.com/icon.png" />
        </div>
        <div class="lg:col-span-2 flex flex-wrap gap-2">
          <Button type="submit" disabled={createLoading || ($overview && $overview.usage.apps >= ($overview.entitlements?.maxApps ?? $overview.usage.apps))}>
            {createLoading ? 'Creating...' : 'Create app'}
          </Button>
          <Button type="button" variant="secondary" onclick={beginCreate}>Reset</Button>
        </div>
        {#if createError}
          <div class="lg:col-span-2 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{createError}</div>
        {/if}
      </form>
    </Card>
  {:else}
    <Card class="border-surface-200 bg-surface-50">
      <p class="text-sm leading-6 text-surface-600">
        You have read access to apps. App creation and edits stay hidden because this session is a member, not an administrator.
      </p>
    </Card>
  {/if}

  <Card class="space-y-4">
    <div class="flex items-center justify-between gap-3">
      <div>
        <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">App list</h2>
        <p class="mt-1 text-sm leading-6 text-surface-600">
          Client IDs are shown for reference. Redirect URIs are written exactly as registered.
        </p>
      </div>
      <Button variant="secondary" onclick={() => void loadApps()}>Reload</Button>
    </div>

    {#if loading}
      <div class="space-y-3" aria-label="Loading apps">
        <div class="h-24 rounded-2xl bg-surface-100"></div>
        <div class="h-24 rounded-2xl bg-surface-100"></div>
      </div>
    {:else if apps.length === 0}
      <div class="rounded-2xl border border-dotted border-surface-200 bg-surface-50 p-6">
        <h3 class="text-base font-semibold text-surface-900">No apps yet</h3>
        <p class="mt-2 max-w-2xl text-sm leading-6 text-surface-600">
          Create the first app to start the tenant activation flow. The console will enforce redirect origin rules before the request reaches the API.
        </p>
      </div>
    {:else}
      <div class="space-y-3">
        {#each apps as app}
          <article class="rounded-2xl border border-surface-200 bg-white p-4">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div class="min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <h3 class="text-base font-semibold text-surface-900">{app.name}</h3>
                  <span class="rounded-full border border-surface-200 bg-surface-50 px-2.5 py-1 text-xs font-semibold text-surface-600">{app.type}</span>
                  {#if app.disabled}
                    <span class="rounded-full border border-surface-200 bg-surface-50 px-2.5 py-1 text-xs font-semibold text-surface-600">Disabled</span>
                  {/if}
                </div>
                <p class="mt-2 font-mono text-xs text-surface-500 break-all">{app.clientId}</p>
                <p class="mt-2 text-sm leading-6 text-surface-600">
                  {app.uri ?? 'No metadata URL'}
                </p>
              </div>

              <div class="flex flex-wrap gap-2">
                {#if $overview?.organization.role === 'ADMIN'}
                  <Button variant="secondary" type="button" onclick={() => beginEdit(app)}>
                    {editingAppId === app.id ? 'Editing' : 'Edit'}
                  </Button>
                {/if}
              </div>
            </div>

            <div class="mt-4 grid gap-3 lg:grid-cols-[1fr_1fr]">
              <div class="rounded-2xl border border-surface-200 bg-surface-50 p-3">
                <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Redirect URIs</div>
                <ul class="mt-2 space-y-1 text-sm text-surface-700">
                  {#each app.redirectUris as redirectUri}
                    <li class="break-all font-mono text-xs text-surface-700">{redirectUri}</li>
                  {/each}
                </ul>
              </div>
              <div class="rounded-2xl border border-surface-200 bg-surface-50 p-3">
                <div class="text-xs font-semibold uppercase tracking-[0.08em] text-surface-500">Notes</div>
                <p class="mt-2 text-sm leading-6 text-surface-600">
                  {#if app.icon}
                    Icon URL configured. {app.disabled ? 'The app is disabled.' : 'The app is active.'}
                  {:else}
                    No icon URL configured. {app.disabled ? 'The app is disabled.' : 'The app is active.'}
                  {/if}
                </p>
              </div>
            </div>

            {#if editingAppId === app.id}
              <form class="mt-4 space-y-4 border-t border-dotted border-surface-200 pt-4" onsubmit={(event) => { event.preventDefault(); void saveEdit(app); }}>
                <div class="grid gap-4 lg:grid-cols-2">
                  <div class="space-y-2">
                    <label class="text-sm font-semibold text-surface-900" for={`edit-name-${app.id}`}>App name</label>
                    <Input id={`edit-name-${app.id}`} bind:value={editName} required />
                  </div>
                  <div class="space-y-2">
                    <label class="text-sm font-semibold text-surface-900" for={`edit-type-${app.id}`}>App type</label>
                    <select
                      id={`edit-type-${app.id}`}
                      class="h-10 w-full rounded-xl border border-surface-200 bg-white px-3 text-sm text-surface-900 focus-visible:border-primary-500 focus-visible:ring-2 focus-visible:ring-primary-200"
                      bind:value={editType}
                    >
                      <option value="spa">Browser app</option>
                      <option value="native">Native app</option>
                    </select>
                  </div>
                  <div class="space-y-2 lg:col-span-2">
                    <label class="text-sm font-semibold text-surface-900" for={`edit-redirect-${app.id}`}>Redirect URIs</label>
                    <textarea
                      id={`edit-redirect-${app.id}`}
                      bind:value={editRedirectUris}
                      rows="4"
                      class="w-full rounded-2xl border border-surface-200 bg-white px-3 py-3 text-sm text-surface-900 placeholder:text-surface-400 focus-visible:border-primary-500 focus-visible:ring-2 focus-visible:ring-primary-200"
                    ></textarea>
                  </div>
                  <div class="space-y-2">
                    <label class="text-sm font-semibold text-surface-900" for={`edit-uri-${app.id}`}>Metadata URL</label>
                    <Input id={`edit-uri-${app.id}`} bind:value={editUri} />
                  </div>
                  <div class="space-y-2">
                    <label class="text-sm font-semibold text-surface-900" for={`edit-icon-${app.id}`}>Icon URL</label>
                    <Input id={`edit-icon-${app.id}`} bind:value={editIcon} />
                  </div>
                </div>

                <label class="flex items-center gap-2 text-sm text-surface-700">
                  <input type="checkbox" bind:checked={editDisabled} class="h-4 w-4 rounded border-surface-300 text-primary-600 focus-visible:ring-primary-200" />
                  Disable this app
                </label>

                <div class="flex flex-wrap gap-2">
                  <Button type="submit" disabled={editLoading}>{editLoading ? 'Saving...' : 'Save changes'}</Button>
                  <Button type="button" variant="secondary" onclick={cancelEdit}>Cancel</Button>
                </div>

                {#if editError}
                  <div class="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{editError}</div>
                {/if}
              </form>
            {/if}
          </article>
        {/each}
      </div>
    {/if}
  </Card>
</div>
