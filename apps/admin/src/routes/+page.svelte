<script lang="ts">
  // Admin dashboard home page
</script>

<div class="max-w-4xl">
  <h1 class="text-4xl font-bold text-surface-900 mb-4">OpenKey Admin Dashboard</h1>
  <p class="text-surface-600 text-lg mb-8">
    Manage OAuth applications and developer billing
  </p>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
    <a
      href="/apps"
      class="block p-6 bg-white border border-surface-200 rounded-lg hover:border-primary-500 transition-colors no-underline"
    >
      <h2 class="text-2xl font-semibold text-surface-900 mb-2">Applications</h2>
      <p class="text-surface-600">View and manage registered OAuth applications</p>
    </a>

    <a
      href="/billing"
      class="block p-6 bg-white border border-surface-200 rounded-lg hover:border-primary-500 transition-colors no-underline"
    >
      <h2 class="text-2xl font-semibold text-surface-900 mb-2">Billing</h2>
      <p class="text-surface-600">Manage developer accounts and Stripe subscriptions</p>
    </a>
  </div>
</div>
