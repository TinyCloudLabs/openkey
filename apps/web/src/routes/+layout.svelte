<script lang="ts">
  import '../app.css';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();
</script>

<svelte:head>
  <title>OpenKey</title>
  <meta name="description" content="Passkey-first authentication for Ethereum keys" />
</svelte:head>

<div class="min-h-screen flex flex-col">
  <header class="border-b border-surface-800 px-6 py-4">
    <nav class="max-w-6xl mx-auto flex items-center justify-between">
      <a href="/" class="text-2xl font-bold text-surface-50 no-underline">OpenKey</a>
      <div class="flex items-center gap-4">
        <a href="/dashboard" class="text-surface-400 hover:text-surface-50 transition-colors no-underline">
          Dashboard
        </a>
      </div>
    </nav>
  </header>

  <main class="flex-1 max-w-6xl mx-auto w-full px-6 py-8">
    {@render children()}
  </main>

  <footer class="border-t border-surface-800 px-6 py-6 text-center text-surface-500">
    <p>OpenKey - Your keys, secured by passkeys</p>
  </footer>
</div>
