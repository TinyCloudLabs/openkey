<script lang="ts">
  import '../app.css';
  import { page } from '$app/stores';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();
</script>

<svelte:head>
  <title>OpenKey Admin</title>
  <meta name="description" content="OpenKey Admin Dashboard" />
</svelte:head>

<div class="min-h-screen flex flex-col">
  <header class="border-b border-surface-200 bg-white px-6 py-4">
    <nav class="max-w-7xl mx-auto flex items-center justify-between">
      <a href="/" class="text-2xl font-bold text-surface-900 no-underline">OpenKey Admin</a>
      <div class="flex items-center gap-4">
        <a
          href="/apps"
          class="text-surface-500 hover:text-surface-900 transition-colors no-underline"
          class:text-surface-900={$page.url.pathname.startsWith('/apps')}
        >
          Apps
        </a>
        <a
          href="/billing"
          class="text-surface-500 hover:text-surface-900 transition-colors no-underline"
          class:text-surface-900={$page.url.pathname.startsWith('/billing')}
        >
          Billing
        </a>
      </div>
    </nav>
  </header>

  <main class="flex-1 max-w-7xl mx-auto w-full px-6 py-8">
    {@render children()}
  </main>

  <footer class="border-t border-surface-200 px-6 py-6 text-center text-surface-400">
    <p>OpenKey Admin Dashboard</p>
  </footer>
</div>
