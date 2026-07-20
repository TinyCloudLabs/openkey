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
    default: 'border border-primary-600 bg-primary-600 text-white hover:bg-primary-700 hover:border-primary-700',
    secondary: 'border border-surface-200 bg-white text-surface-900 hover:border-primary-300 hover:text-primary-700',
    ghost: 'border border-transparent bg-transparent text-surface-600 hover:border-surface-200 hover:bg-surface-100 hover:text-surface-900',
    link: 'border border-transparent bg-transparent px-0 text-surface-700 underline-offset-4 hover:text-primary-600 hover:underline',
  };

  const sizes: Record<Size, string> = {
    default: 'h-10 px-4 py-2',
    sm: 'h-9 px-3 text-sm',
    lg: 'h-11 px-5 text-base',
    icon: 'h-10 w-10 px-0',
  };

  const baseClasses = $derived(cn(
    'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full font-semibold transition-colors',
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-300 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-50',
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
