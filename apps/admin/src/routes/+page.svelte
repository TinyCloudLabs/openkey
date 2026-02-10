<script lang="ts">
  import { page } from '$app/stores';

  let { data } = $props();

  let mauPercent = $derived(
    data.developerAccount && data.developerAccount.mauLimit > 0
      ? Math.min(100, Math.round((data.currentMau / data.developerAccount.mauLimit) * 100))
      : 0
  );

  let displayName = $derived(
    $page.data.user?.name || $page.data.user?.email || 'Developer'
  );
</script>

<svelte:head>
  <title>Dashboard - OpenKey Admin</title>
</svelte:head>

<div class="max-w-5xl">
  <h1 class="text-3xl font-bold text-surface-900 mb-1">
    Welcome, {displayName}
  </h1>
  <p class="text-surface-500 mb-8">Here's an overview of your developer account.</p>

  <!-- Stats Cards -->
  <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
    <!-- MAU Gauge Card -->
    <div class="bg-white border border-surface-200 rounded-lg p-6">
      <h2 class="text-sm font-medium text-surface-500 uppercase tracking-wide mb-3">
        Monthly Active Users
      </h2>
      <div class="flex items-end gap-2 mb-3">
        <span class="text-3xl font-bold text-surface-900">{data.currentMau.toLocaleString()}</span>
        <span class="text-surface-400 text-sm mb-1">
          / {data.developerAccount?.mauLimit.toLocaleString() ?? '---'}
        </span>
      </div>
      <!-- Gauge bar -->
      <div class="w-full bg-surface-100 rounded-full h-2">
        <div
          class="h-2 rounded-full transition-all duration-300"
          class:bg-primary-500={mauPercent < 80}
          class:bg-yellow-500={mauPercent >= 80 && mauPercent < 100}
          class:bg-red-500={mauPercent >= 100}
          style="width: {mauPercent}%"
        ></div>
      </div>
      <p class="text-xs text-surface-400 mt-2">{mauPercent}% of plan limit</p>
    </div>

    <!-- Plan Card -->
    <div class="bg-white border border-surface-200 rounded-lg p-6">
      <h2 class="text-sm font-medium text-surface-500 uppercase tracking-wide mb-3">
        Current Plan
      </h2>
      <span class="text-3xl font-bold text-surface-900">
        {data.developerAccount?.plan ?? 'FREE'}
      </span>
      <p class="text-sm text-surface-400 mt-2">
        Up to {data.developerAccount?.appLimit ?? 3} apps
      </p>
      <a
        href="/billing"
        class="inline-block mt-3 text-sm text-primary-600 hover:text-primary-700 no-underline font-medium"
      >
        Manage billing
      </a>
    </div>

    <!-- Apps Card -->
    <div class="bg-white border border-surface-200 rounded-lg p-6">
      <h2 class="text-sm font-medium text-surface-500 uppercase tracking-wide mb-3">
        Applications
      </h2>
      <span class="text-3xl font-bold text-surface-900">{data.apps.length}</span>
      <p class="text-sm text-surface-400 mt-2">
        {data.apps.length === 1 ? '1 registered app' : `${data.apps.length} registered apps`}
      </p>
      <a
        href="/apps/new"
        class="inline-block mt-3 text-sm text-primary-600 hover:text-primary-700 no-underline font-medium"
      >
        Create new app
      </a>
    </div>
  </div>

  <!-- App List -->
  <div class="bg-white border border-surface-200 rounded-lg">
    <div class="flex items-center justify-between px-6 py-4 border-b border-surface-200">
      <h2 class="text-lg font-semibold text-surface-900">Your Applications</h2>
      <a
        href="/apps/new"
        class="px-4 py-2 bg-primary-600 text-white text-sm rounded-md font-medium hover:bg-primary-700 transition-colors no-underline"
      >
        Create New App
      </a>
    </div>

    {#if data.apps.length === 0}
      <div class="px-6 py-12 text-center">
        <p class="text-surface-500 mb-4">You haven't created any applications yet.</p>
        <a
          href="/apps/new"
          class="inline-block px-4 py-2 bg-primary-600 text-white text-sm rounded-md font-medium hover:bg-primary-700 transition-colors no-underline"
        >
          Create Your First App
        </a>
      </div>
    {:else}
      <div class="divide-y divide-surface-100">
        {#each data.apps as app}
          <a
            href="/apps/{app.id}"
            class="flex items-center justify-between px-6 py-4 hover:bg-surface-50 transition-colors no-underline"
          >
            <div>
              <h3 class="font-medium text-surface-900">{app.name}</h3>
              <p class="text-sm text-surface-400 font-mono mt-0.5">{app.clientId}</p>
            </div>
            <div class="flex items-center gap-3">
              {#if app.type}
                <span
                  class="px-2 py-0.5 text-xs font-medium rounded-full"
                  class:bg-primary-100={app.type === 'web'}
                  class:text-primary-700={app.type === 'web'}
                  class:bg-green-100={app.type === 'native'}
                  class:text-green-700={app.type === 'native'}
                  class:bg-blue-100={app.type === 'spa'}
                  class:text-blue-700={app.type === 'spa'}
                >
                  {app.type}
                </span>
              {/if}
              <span class="text-sm text-surface-400">
                {new Date(app.createdAt).toLocaleDateString()}
              </span>
            </div>
          </a>
        {/each}
      </div>
    {/if}
  </div>
</div>
