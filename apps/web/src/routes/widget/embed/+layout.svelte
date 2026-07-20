<script lang="ts">
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();
</script>

<div class="openkey-widget-theme flex flex-col" style="background: transparent; margin: 0; padding: 0;">
  {@render children()}
</div>
