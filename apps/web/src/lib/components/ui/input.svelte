<script lang="ts">
  import { cn } from '$lib/utils';
  import type { HTMLInputAttributes } from 'svelte/elements';

  interface Props extends HTMLInputAttributes {
    class?: string;
    value?: string;
  }

  let { class: className, value = $bindable(''), ...restProps }: Props = $props();
</script>

<input
  class={cn(
    'flex h-10 w-full rounded-xl border border-surface-200 bg-white px-3 py-2 text-sm',
    'text-surface-900 placeholder:text-surface-400',
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-surface-300 focus-visible:border-surface-400',
    'disabled:cursor-not-allowed disabled:opacity-50',
    className
  )}
  bind:value
  {...restProps}
/>
