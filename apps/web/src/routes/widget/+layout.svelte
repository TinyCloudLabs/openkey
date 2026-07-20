<script lang="ts">
  import type { Snippet } from 'svelte';
  import { page } from '$app/stores';

  let { children }: { children: Snippet } = $props();

  let isEmbed = $derived($page.url.pathname.startsWith('/widget/embed'));
</script>

{#if isEmbed}
  {@render children()}
{:else}
  <div class="openkey-widget-theme min-h-screen flex flex-col">
    {@render children()}
  </div>
{/if}
