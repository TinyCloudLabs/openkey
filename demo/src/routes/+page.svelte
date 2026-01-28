<script lang="ts">
  import { onMount } from 'svelte';
  import { auth, loadAuthFromStorage, logout } from '$lib/stores';
  import SignMessage from '$lib/components/SignMessage.svelte';

  onMount(() => {
    loadAuthFromStorage();
  });

  function handleLogout() {
    logout();
  }
</script>

<div class="flex flex-col items-center justify-center py-16">
  {#if !$auth.isAuthenticated}
    <!-- Not logged in -->
    <div class="text-center">
      <h1 class="mb-4 text-4xl font-bold text-surface-50">OpenKey Demo</h1>
      <p class="mb-8 text-lg text-surface-400">
        Sign in with your OpenKey account to access signing capabilities
      </p>

      <a
        href="/login"
        class="inline-flex items-center justify-center rounded-lg bg-primary-600 px-8 py-3 text-lg font-semibold text-white transition-colors hover:bg-primary-700"
      >
        Sign in with OpenKey
      </a>
    </div>
  {:else}
    <!-- Logged in -->
    <div class="w-full max-w-lg">
      <div class="mb-8 flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold text-surface-50">Welcome</h1>
          <p class="text-surface-400">Signed in as {$auth.user?.sub}</p>
        </div>
        <button
          onclick={handleLogout}
          class="rounded-lg border border-surface-700 bg-transparent px-4 py-2 text-sm font-medium text-surface-300 transition-colors hover:border-surface-500 hover:text-surface-50"
        >
          Sign Out
        </button>
      </div>

      <!-- Sign Message Section -->
      <SignMessage />
    </div>
  {/if}
</div>
