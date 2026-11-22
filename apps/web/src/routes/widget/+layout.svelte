<script lang="ts">
  import type { Snippet } from 'svelte';
  import { page } from '$app/stores';
  import FramedTermsNotice from '$lib/components/auth/framed-terms-notice.svelte';
  import { framedTermsRequired } from '$lib/terms';

  let { children }: { children: Snippet } = $props();

  let isEmbed = $derived($page.url.pathname.startsWith('/widget/embed'));
</script>

{#snippet content()}
  {#if $framedTermsRequired}
    <FramedTermsNotice />
  {:else}
    {@render children()}
  {/if}
{/snippet}

{#if isEmbed}
  {@render content()}
{:else}
  <div class="openkey-widget-theme min-h-screen flex flex-col">
    {@render content()}
  </div>
{/if}
