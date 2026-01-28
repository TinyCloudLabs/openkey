<script lang="ts">
  import '../app.css';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();
</script>

<svelte:head>
  <title>OpenKey Demo</title>
  <meta name="description" content="Demo application for OpenKey OAuth authentication" />
</svelte:head>

<div class="min-h-screen flex flex-col">
  <header class="border-b border-surface-800 px-6 py-4">
    <nav class="max-w-4xl mx-auto flex items-center justify-between">
      <a href="/" class="text-xl font-bold text-surface-50 no-underline">
        OpenKey Demo
      </a>
    </nav>
  </header>

  <main class="flex-1 max-w-4xl mx-auto w-full px-6 py-8">
    {@render children()}
  </main>

  <footer class="border-t border-surface-800 px-6 py-6 text-center text-surface-500 text-sm">
    <p>Demo application powered by OpenKey</p>
  </footer>
</div>
