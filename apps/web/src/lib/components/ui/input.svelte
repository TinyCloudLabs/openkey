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
    'flex h-10 w-full rounded-lg border border-surface-700 bg-surface-900 px-3 py-2 text-sm',
    'text-surface-50 placeholder:text-surface-500',
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 focus-visible:border-primary-500',
    'disabled:cursor-not-allowed disabled:opacity-50',
    className
  )}
  bind:value
  {...restProps}
/>
