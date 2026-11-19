<script lang="ts">
  // The few line icons the approval pages use. Decorative: the words beside them carry the meaning.
  let { name, class: className = 'h-[18px] w-[18px]' }: { name: 'key' | 'shield' | 'chev' | 'alert'; class?: string } = $props();
</script>

<svg
  class="{className} flex-none"
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="1.8"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
>
  {#if name === 'key'}
    <path d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
  {:else if name === 'shield'}
    <path d="M12 3l7.5 3v5.2c0 4.5-3 8.3-7.5 9.8-4.5-1.5-7.5-5.3-7.5-9.8V6L12 3z" />
    <path d="M9 12l2.2 2.2L15.2 10" />
  {:else if name === 'chev'}
    <path d="M7 10l5 5 5-5" />
  {:else}
    <path d="M12 8.5v4.5M12 16.4v.1M10.3 4.2L2.9 17a2 2 0 001.7 3h14.8a2 2 0 001.7-3L13.7 4.2a2 2 0 00-3.4 0z" />
  {/if}
</svg>
