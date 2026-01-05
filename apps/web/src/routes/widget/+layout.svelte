<script lang="ts">
  import type { Snippet } from 'svelte';
  import { onMount } from 'svelte';
  import { page } from '$app/stores';

  let { children }: { children: Snippet } = $props();

  // Notify parent when widget is ready
  onMount(() => {
    const origin = $page.url.searchParams.get('origin');
    if (origin && window.opener) {
      window.opener.postMessage({ type: 'openkey:ready' }, origin);
    } else if (origin && window.parent !== window) {
      window.parent.postMessage({ type: 'openkey:ready' }, origin);
    }
  });
</script>

<div class="widget">
  {@render children()}
</div>

<style>
  :global(body) {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0a0a0a;
    color: #fafafa;
  }

  .widget {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    padding: 1.5rem;
  }
</style>
