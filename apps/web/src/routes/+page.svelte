<script lang="ts">
  import { authClient } from '$lib/auth-client';
  import Card from '$lib/components/ui/card.svelte';

  const session = authClient.useSession();
</script>

<div class="min-h-screen bg-surface-950 text-surface-50">
  <div class="mx-auto max-w-6xl px-6 py-24 text-center">
    <!-- Hero Section -->
    <h1 class="mb-4 text-6xl font-bold tracking-tight bg-gradient-to-br from-primary-600 to-primary-800 bg-clip-text text-transparent">
      OpenKey
    </h1>
    <p class="mb-16 text-xl text-surface-400">
      Passkey-first authentication for Ethereum keys
    </p>

    <!-- Feature Cards -->
    <div class="mb-16 grid gap-8 md:grid-cols-3">
      <Card class="text-left">
        <h3 class="mb-2 text-lg font-semibold text-surface-50">Passkey Security</h3>
        <p class="text-surface-400">No passwords to remember. Your biometrics are your key.</p>
      </Card>

      <Card class="text-left">
        <h3 class="mb-2 text-lg font-semibold text-surface-50">TEE Protected</h3>
        <p class="text-surface-400">Private keys secured in a Trusted Execution Environment.</p>
      </Card>

      <Card class="text-left">
        <h3 class="mb-2 text-lg font-semibold text-surface-50">Easy Integration</h3>
        <p class="text-surface-400">Simple SDK for any web application.</p>
      </Card>
    </div>

    <!-- CTA Buttons -->
    <div class="flex justify-center gap-4">
      {#if $session.data}
        <a
          href="/dashboard"
          class="inline-flex items-center justify-center rounded-lg bg-gradient-to-r from-primary-600 to-primary-800 px-8 py-3 text-lg font-semibold text-white shadow-lg transition-all hover:-translate-y-0.5 hover:shadow-primary-600/40"
        >
          Go to Dashboard
        </a>
      {:else}
        <a
          href="/auth/login"
          class="inline-flex items-center justify-center rounded-lg bg-gradient-to-r from-primary-600 to-primary-800 px-8 py-3 text-lg font-semibold text-white shadow-lg transition-all hover:-translate-y-0.5 hover:shadow-primary-600/40"
        >
          Get Started
        </a>
        <a
          href="/auth/login"
          class="inline-flex items-center justify-center rounded-lg border border-surface-700 bg-transparent px-8 py-3 text-lg font-semibold text-surface-50 transition-colors hover:border-surface-500"
        >
          Sign In
        </a>
      {/if}
    </div>
  </div>
</div>
