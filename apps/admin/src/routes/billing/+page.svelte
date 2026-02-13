<script lang="ts">
  let { data } = $props();

  let loading = $state<string | null>(null);
  let errorMessage = $state<string | null>(null);

  const planFeatures = {
    FREE: {
      mau: '1,000 MAU',
      apps: '3 apps',
      support: 'Community support',
      features: ['OAuth 2.1 provider', 'Passkey authentication', 'Basic analytics'],
    },
    PRO: {
      mau: '10,000 MAU',
      apps: '10 apps',
      support: 'Email support',
      features: ['Everything in Free', 'Priority rate limits', 'Advanced analytics', 'Custom branding'],
    },
    SCALE: {
      mau: '100,000 MAU',
      apps: '50 apps',
      support: 'Priority support',
      features: ['Everything in Pro', 'SLA guarantee', 'Dedicated infrastructure', 'Webhook events'],
    },
    ENTERPRISE: {
      mau: 'Unlimited',
      apps: 'Unlimited',
      support: 'Dedicated support',
      features: ['Everything in Scale', 'Custom contracts', 'On-premise option', 'Dedicated account manager'],
    },
  } as const;

  const planPricing: Record<string, string> = {
    FREE: '$0',
    PRO: '$49',
    SCALE: '$199',
    ENTERPRISE: 'Custom',
  };

  function formatDate(timestamp: number): string {
    return new Date(timestamp * 1000).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  }

  function formatCardBrand(brand: string): string {
    const brands: Record<string, string> = {
      visa: 'Visa',
      mastercard: 'Mastercard',
      amex: 'American Express',
      discover: 'Discover',
    };
    return brands[brand] || brand.charAt(0).toUpperCase() + brand.slice(1);
  }

  function billingStateLabel(state: string): { text: string; className: string } {
    switch (state) {
      case 'ACTIVE':
        return { text: 'Active', className: 'bg-green-100 text-green-800' };
      case 'PAST_DUE':
        return { text: 'Past Due', className: 'bg-yellow-100 text-yellow-800' };
      case 'CANCELLED':
        return { text: 'Cancelled', className: 'bg-red-100 text-red-800' };
      default:
        return { text: 'Free', className: 'bg-surface-100 text-surface-700' };
    }
  }

  async function handleUpgrade(planKey: string) {
    if (planKey === 'ENTERPRISE') return;
    loading = planKey;
    errorMessage = null;

    try {
      const res = await fetch('/api/stripe/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan: planKey }),
      });

      const result = await res.json();

      if (!res.ok) {
        errorMessage = result.error || 'Failed to create checkout session';
        return;
      }

      if (result.url) {
        window.location.href = result.url;
      }
    } catch {
      errorMessage = 'An unexpected error occurred';
    } finally {
      loading = null;
    }
  }

  async function handleManageSubscription() {
    loading = 'portal';
    errorMessage = null;

    try {
      const res = await fetch('/api/stripe/portal', {
        method: 'POST',
      });

      const result = await res.json();

      if (!res.ok) {
        errorMessage = result.error || 'Failed to open customer portal';
        return;
      }

      if (result.url) {
        window.location.href = result.url;
      }
    } catch {
      errorMessage = 'An unexpected error occurred';
    } finally {
      loading = null;
    }
  }

  const stateInfo = $derived(billingStateLabel(data.billingState));
  const isEnterprise = $derived(data.plan === 'ENTERPRISE');
  const hasActiveSubscription = $derived(data.billingState === 'ACTIVE' || data.billingState === 'PAST_DUE');

  // Check URL params for success/cancel messaging
  let successMessage = $state<string | null>(null);
  if (typeof window !== 'undefined') {
    const params = new URLSearchParams(window.location.search);
    if (params.get('success') === 'true') {
      successMessage = 'Your subscription has been activated. It may take a moment for changes to appear.';
    } else if (params.get('canceled') === 'true') {
      successMessage = null;
      errorMessage = 'Checkout was canceled. No changes were made.';
    }
  }
</script>

<div class="max-w-6xl">
  <h1 class="text-3xl font-bold text-surface-900 mb-2">Billing & Subscriptions</h1>
  <p class="text-surface-600 mb-8">
    Manage your plan, payment method, and subscription details.
  </p>

  <!-- Success / Error banners -->
  {#if successMessage}
    <div class="mb-6 rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-green-800">
      {successMessage}
    </div>
  {/if}

  {#if errorMessage}
    <div class="mb-6 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-red-800">
      {errorMessage}
    </div>
  {/if}

  <!-- Current Plan Card -->
  <div class="bg-white border border-surface-200 rounded-lg p-6 mb-8">
    <div class="flex items-start justify-between">
      <div>
        <div class="flex items-center gap-3 mb-2">
          <h2 class="text-xl font-semibold text-surface-900">Current Plan</h2>
          <span class="px-2.5 py-0.5 rounded-full text-xs font-medium {stateInfo.className}">
            {stateInfo.text}
          </span>
        </div>
        <p class="text-2xl font-bold text-primary-600 mb-1">{data.planName}</p>
        <div class="text-surface-500 text-sm space-y-1">
          <p>
            {data.mauLimit === -1 ? 'Unlimited' : data.mauLimit.toLocaleString()} monthly active users
          </p>
          <p>
            {data.appLimit === -1 ? 'Unlimited' : data.appLimit} applications
          </p>
        </div>
      </div>

      <div class="text-right">
        {#if data.subscription}
          <p class="text-sm text-surface-500">
            {#if data.subscription.cancelAtPeriodEnd}
              Cancels on {formatDate(data.subscription.currentPeriodEnd)}
            {:else}
              Next billing date: {formatDate(data.subscription.currentPeriodEnd)}
            {/if}
          </p>
        {/if}

        {#if hasActiveSubscription}
          <button
            onclick={handleManageSubscription}
            disabled={loading === 'portal'}
            class="mt-3 px-4 py-2 text-sm font-medium text-primary-700 bg-primary-50 hover:bg-primary-100 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading === 'portal' ? 'Opening...' : 'Manage Subscription'}
          </button>
        {/if}
      </div>
    </div>

    <!-- Payment Method -->
    {#if data.subscription?.paymentMethod}
      <div class="mt-4 pt-4 border-t border-surface-100">
        <p class="text-sm text-surface-500">
          Payment method:
          <span class="font-medium text-surface-700">
            {formatCardBrand(data.subscription.paymentMethod.brand)} ending in {data.subscription.paymentMethod.last4}
          </span>
        </p>
      </div>
    {/if}
  </div>

  <!-- Plan Comparison Grid -->
  <h2 class="text-xl font-semibold text-surface-900 mb-4">Available Plans</h2>
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
    {#each Object.entries(planFeatures) as [key, features]}
      {@const isCurrent = key === data.plan}
      {@const isPopular = key === 'PRO'}
      <div
        class="relative bg-white border rounded-lg p-6 flex flex-col {isCurrent
          ? 'border-primary-300 ring-2 ring-primary-100'
          : 'border-surface-200'}"
      >
        {#if isPopular}
          <div class="absolute -top-3 left-1/2 -translate-x-1/2">
            <span class="bg-primary-600 text-white text-xs font-medium px-3 py-1 rounded-full">
              Most Popular
            </span>
          </div>
        {/if}

        <div class="mb-4">
          <h3 class="text-lg font-semibold text-surface-900">{data.plans[key as keyof typeof data.plans].name}</h3>
          <p class="text-3xl font-bold text-surface-900 mt-2">
            {planPricing[key]}
            {#if key !== 'FREE' && key !== 'ENTERPRISE'}
              <span class="text-sm font-normal text-surface-500">/month</span>
            {/if}
          </p>
        </div>

        <div class="text-sm text-surface-600 mb-4 space-y-1">
          <p class="font-medium text-surface-800">{features.mau}</p>
          <p class="font-medium text-surface-800">{features.apps}</p>
          <p>{features.support}</p>
        </div>

        <ul class="text-sm text-surface-600 space-y-2 mb-6 flex-1">
          {#each features.features as feature}
            <li class="flex items-start gap-2">
              <svg class="w-4 h-4 text-green-500 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              {feature}
            </li>
          {/each}
        </ul>

        <div class="mt-auto">
          {#if isCurrent}
            <div class="w-full py-2.5 text-center text-sm font-medium text-primary-700 bg-primary-50 rounded-lg">
              Current Plan
            </div>
          {:else if key === 'ENTERPRISE'}
            <a
              href="mailto:sales@openkey.so"
              class="block w-full py-2.5 text-center text-sm font-medium text-surface-700 bg-surface-100 hover:bg-surface-200 rounded-lg transition-colors no-underline"
            >
              Contact Sales
            </a>
          {:else if key === 'FREE' && data.plan !== 'FREE'}
            <button
              onclick={handleManageSubscription}
              disabled={loading === 'portal'}
              class="w-full py-2.5 text-sm font-medium text-surface-700 bg-surface-100 hover:bg-surface-200 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading === 'portal' ? 'Opening...' : 'Downgrade'}
            </button>
          {:else}
            <button
              onclick={() => handleUpgrade(key)}
              disabled={loading === key}
              class="w-full py-2.5 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading === key ? 'Redirecting...' : 'Upgrade'}
            </button>
          {/if}
        </div>
      </div>
    {/each}
  </div>
</div>
