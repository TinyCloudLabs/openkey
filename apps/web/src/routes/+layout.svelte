<script lang="ts">
  import '../app.css';
  import { page } from '$app/stores';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();

  let isEmbed = $derived($page.url.pathname.startsWith('/widget/embed'));
  let isFullScreen = $derived(
    $page.url.pathname === '/' ||
    $page.url.pathname.startsWith('/auth/') ||
    $page.url.pathname.startsWith('/managed/register') ||
    $page.url.pathname.startsWith('/delegate') ||
    $page.url.pathname.startsWith('/console') ||
    isEmbed
  );
</script>

<svelte:head>
  <title>OpenKey</title>
  <meta name="description" content="Passkey-first authentication for Ethereum keys" />
</svelte:head>

{#if isFullScreen}
  {@render children()}
{:else}
  <div class="min-h-screen flex flex-col">
    <header class="border-b border-surface-200/80 bg-surface-50/90 backdrop-blur px-5 py-4">
      <nav class="mx-auto flex max-w-6xl items-center justify-between gap-4">
        <a href="/" class="flex items-center gap-3 text-[15px] font-semibold tracking-[-0.03em] text-surface-900 no-underline">
          <span class="inline-grid h-8 w-8 place-items-center rounded-full bg-primary-600 font-mono text-[12px] text-white">OK</span>
          OpenKey Account
        </a>
        <div class="flex items-center gap-2 overflow-x-auto">
          <a href="/dashboard" class="rounded-full px-3 py-1.5 text-sm text-surface-500 no-underline transition-colors hover:bg-surface-100 hover:text-surface-900">
            Dashboard
          </a>
          <a href="/dashboard/api-keys" class="rounded-full px-3 py-1.5 text-sm text-surface-500 no-underline transition-colors hover:bg-surface-100 hover:text-surface-900">
            API keys
          </a>
          <a href="/dashboard/managed-accounts" class="rounded-full px-3 py-1.5 text-sm text-surface-500 no-underline transition-colors hover:bg-surface-100 hover:text-surface-900">
            Connected apps
          </a>
          <a href="/dashboard/organizations" class="rounded-full px-3 py-1.5 text-sm text-surface-500 no-underline transition-colors hover:bg-surface-100 hover:text-surface-900">
            Organizations
          </a>
          <a href="/console" class="rounded-full border border-primary-200 bg-primary-50 px-3 py-1.5 text-sm font-semibold text-primary-700 no-underline transition-colors hover:bg-primary-100">
            Console
          </a>
        </div>
      </nav>
    </header>

    <main class="flex-1 max-w-6xl mx-auto w-full px-6 py-8">
      {@render children()}
    </main>

    <footer class="border-t border-surface-200/80 px-6 py-6 text-center text-sm text-surface-500">
      <p>OpenKey Account and OpenKey Console</p>
    </footer>
  </div>
{/if}
