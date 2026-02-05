<script lang="ts">
  import type { Snippet } from 'svelte';
  import { onMount } from 'svelte';
  import { page } from '$app/stores';

  let { children }: { children: Snippet } = $props();

  // NOTE: Ready message is sent by individual widget pages AFTER they set up their message listeners
  // This ensures the parent SDK's response arrives after the listener is in place
</script>

<div class="min-h-screen flex flex-col p-6">
  {@render children()}
</div>
