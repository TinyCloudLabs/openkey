<script lang="ts">
  import { cn } from '$lib/utils';
  import type { Snippet } from 'svelte';
  import type { HTMLButtonAttributes, HTMLAnchorAttributes } from 'svelte/elements';

  type Variant = 'default' | 'secondary' | 'ghost' | 'link';
  type Size = 'default' | 'sm' | 'lg' | 'icon';

  interface Props extends Omit<HTMLButtonAttributes & HTMLAnchorAttributes, 'children'> {
    variant?: Variant;
    size?: Size;
    class?: string;
    href?: string;
    children: Snippet;
  }

  let {
    variant = 'default',
    size = 'default',
    class: className,
    href,
    children,
    ...restProps
  }: Props = $props();

  const variants: Record<Variant, string> = {
    default: 'bg-surface-900 text-white hover:bg-surface-800 shadow-sm',
    secondary: 'bg-white text-surface-600 hover:bg-surface-100 border border-surface-200',
    ghost: 'hover:bg-surface-100 text-surface-500 hover:text-surface-900',
    link: 'text-surface-600 underline-offset-4 hover:underline hover:text-surface-900',
  };

  const sizes: Record<Size, string> = {
    default: 'h-10 px-4 py-2',
    sm: 'h-9 px-3 text-sm',
    lg: 'h-11 px-8 text-lg',
    icon: 'h-10 w-10',
  };

  const baseClasses = $derived(cn(
    'inline-flex items-center justify-center whitespace-nowrap rounded-xl font-medium transition-colors',
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-surface-400 focus-visible:ring-offset-2 focus-visible:ring-offset-white',
    'disabled:pointer-events-none disabled:opacity-50',
    variants[variant],
    sizes[size],
    className
  ));
</script>

{#if href}
  <a {href} class={baseClasses} {...restProps}>
    {@render children()}
  </a>
{:else}
  <button class={baseClasses} {...restProps}>
    {@render children()}
  </button>
{/if}
