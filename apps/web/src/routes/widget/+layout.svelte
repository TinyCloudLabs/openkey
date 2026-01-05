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

<div class="min-h-screen flex flex-col p-6">
  {@render children()}
</div>
