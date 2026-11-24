<script lang="ts">
  // What every approval page shows from first paint until there is something to read.
  // Every phase of the page is always listed and only the lit one changes, so the card never changes height.
  import Icon from '$lib/components/approval/icon.svelte';
  import { LOADER } from '@openkey/sdk/approval-copy';

  type Phase = keyof typeof LOADER.phases;

  interface Props {
    /** The phases this page goes through, in order. */
    phases: readonly Phase[];
    /** The phase that is happening now. */
    lit: Phase;
  }

  let { phases, lit }: Props = $props();
</script>

<div class="relative my-[26px] mb-[22px] grid h-16 w-16 place-items-center" aria-hidden="true">
  <span class="absolute inset-0 animate-spin rounded-full border-2 border-surface-200 border-t-surface-950"></span>
  <span class="grid h-10 w-10 place-items-center rounded-xl bg-linear-to-br from-surface-800 to-surface-950 text-white">
    <Icon name="key" class="h-[22px] w-[22px]" />
  </span>
</div>
<h1 class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{LOADER.heading}</h1>
<ul role="status" class="mx-0 mt-5 mb-1.5 grid list-none gap-[9px] p-0 text-left text-sm text-surface-400">
  {#each phases as phase (phase)}
    <li class="flex items-center gap-2.5 {phase === lit ? 'font-semibold text-surface-950' : ''}" aria-current={phase === lit ? 'step' : undefined}>
      <span class="h-2 w-2 flex-none rounded-full border-[1.5px] {phase === lit ? 'animate-pulse border-surface-950 bg-surface-950' : 'border-surface-300'}" aria-hidden="true"></span>
      {LOADER.phases[phase]}
    </li>
  {/each}
</ul>
