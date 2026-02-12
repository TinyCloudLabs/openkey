<script lang="ts">
  let { data } = $props();
  let signingOut = $state(false);

  let planLabel = $derived(
    data.developerAccount?.plan === 'FREE'
      ? 'Free'
      : data.developerAccount?.plan === 'PRO'
        ? 'Pro'
        : data.developerAccount?.plan === 'SCALE'
          ? 'Scale'
          : data.developerAccount?.plan === 'ENTERPRISE'
            ? 'Enterprise'
            : data.developerAccount?.plan ?? 'Free'
  );
</script>

<svelte:head>
  <title>Settings - OpenKey Admin</title>
</svelte:head>

<div class="max-w-3xl">
  <h1 class="text-3xl font-bold text-surface-900 mb-1">Account Settings</h1>
  <p class="text-surface-500 mb-8">Manage your developer account and preferences.</p>

  <!-- Account Info -->
  <div class="bg-white border border-surface-200 rounded-lg mb-6">
    <div class="px-6 py-4 border-b border-surface-200">
      <h2 class="text-lg font-semibold text-surface-900">Account Information</h2>
    </div>
    <div class="px-6 py-5 space-y-4">
      <div class="flex items-center justify-between">
        <div>
          <p class="text-sm font-medium text-surface-500">Email</p>
          <p class="text-surface-900">{data.user?.email ?? '---'}</p>
        </div>
      </div>
      <div class="flex items-center justify-between">
        <div>
          <p class="text-sm font-medium text-surface-500">Name</p>
          <p class="text-surface-900">{data.user?.name ?? 'Not set'}</p>
        </div>
      </div>
      <div class="flex items-center justify-between">
        <div>
          <p class="text-sm font-medium text-surface-500">Member since</p>
          <p class="text-surface-900">
            {data.user?.createdAt
              ? new Date(data.user.createdAt).toLocaleDateString('en-US', {
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric',
                })
              : '---'}
          </p>
        </div>
      </div>
    </div>
  </div>

  <!-- Plan Summary -->
  <div class="bg-white border border-surface-200 rounded-lg mb-6">
    <div class="px-6 py-4 border-b border-surface-200">
      <h2 class="text-lg font-semibold text-surface-900">Plan & Billing</h2>
    </div>
    <div class="px-6 py-5 space-y-4">
      <div class="flex items-center justify-between">
        <div>
          <p class="text-sm font-medium text-surface-500">Current Plan</p>
          <p class="text-surface-900 text-lg font-semibold">{planLabel}</p>
        </div>
        <a
          href="/billing"
          class="px-4 py-2 bg-surface-100 text-surface-700 text-sm rounded-md font-medium hover:bg-surface-200 transition-colors no-underline"
        >
          View Billing
        </a>
      </div>
      <div>
        <p class="text-sm font-medium text-surface-500">MAU Limit</p>
        <p class="text-surface-900">
          {data.developerAccount?.mauLimit.toLocaleString() ?? '1,000'} monthly active users
        </p>
      </div>
      <div>
        <p class="text-sm font-medium text-surface-500">App Limit</p>
        <p class="text-surface-900">
          {data.developerAccount?.appLimit ?? 3} applications
        </p>
      </div>
      <div>
        <p class="text-sm font-medium text-surface-500">Manage Subscription</p>
        <a
          href="/billing"
          class="text-primary-600 hover:text-primary-700 text-sm font-medium no-underline"
        >
          Go to Stripe Customer Portal
        </a>
      </div>
    </div>
  </div>

  <!-- Developer Account Reference -->
  <div class="bg-white border border-surface-200 rounded-lg mb-6">
    <div class="px-6 py-4 border-b border-surface-200">
      <h2 class="text-lg font-semibold text-surface-900">Developer Reference</h2>
    </div>
    <div class="px-6 py-5 space-y-4">
      <div>
        <p class="text-sm font-medium text-surface-500">Developer Account ID</p>
        <p class="text-surface-900 font-mono text-sm">
          {data.developerAccount?.id ?? '---'}
        </p>
        <p class="text-xs text-surface-400 mt-1">Use this ID when contacting support.</p>
      </div>
    </div>
  </div>

  <!-- Sign Out -->
  <div class="bg-white border border-surface-200 rounded-lg">
    <div class="px-6 py-5 flex items-center justify-between">
      <div>
        <h2 class="text-lg font-semibold text-surface-900">Sign Out</h2>
        <p class="text-sm text-surface-500">End your current session.</p>
      </div>
      <form method="POST" action="/auth/signout">
        <button
          type="submit"
          disabled={signingOut}
          onclick={() => { signingOut = true; }}
          class="px-4 py-2 bg-red-50 text-red-700 text-sm rounded-md font-medium hover:bg-red-100 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {signingOut ? 'Signing out...' : 'Sign Out'}
        </button>
      </form>
    </div>
  </div>
</div>
