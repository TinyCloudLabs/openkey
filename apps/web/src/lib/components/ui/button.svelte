<script lang="ts">
  import { cn } from '$lib/utils';
  import type { Snippet } from 'svelte';
  import type { HTMLButtonAttributes } from 'svelte/elements';

  type Variant = 'default' | 'secondary' | 'ghost' | 'link';
  type Size = 'default' | 'sm' | 'lg' | 'icon';

  interface Props extends HTMLButtonAttributes {
    variant?: Variant;
    size?: Size;
    class?: string;
    children: Snippet;
  }

  let {
    variant = 'default',
    size = 'default',
    class: className,
    children,
    ...restProps
  }: Props = $props();

  const variants: Record<Variant, string> = {
    default: 'bg-primary-600 text-white hover:bg-primary-700 shadow-sm',
    secondary: 'bg-surface-800 text-surface-50 hover:bg-surface-700 border border-surface-700',
    ghost: 'hover:bg-surface-800 text-surface-300 hover:text-surface-50',
    link: 'text-primary-400 underline-offset-4 hover:underline',
  };

  const sizes: Record<Size, string> = {
    default: 'h-10 px-4 py-2',
    sm: 'h-9 px-3 text-sm',
    lg: 'h-11 px-8 text-lg',
    icon: 'h-10 w-10',
  };
</script>

<button
  class={cn(
    'inline-flex items-center justify-center whitespace-nowrap rounded-lg font-medium transition-colors',
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-950',
    'disabled:pointer-events-none disabled:opacity-50',
    variants[variant],
    sizes[size],
    className
  )}
  {...restProps}
>
  {@render children()}
</button>
