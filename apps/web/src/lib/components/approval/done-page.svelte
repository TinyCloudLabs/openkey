<script lang="ts" module>
  export type DoneOutcome = 'approved' | 'declined' | 'cancelled' | 'signedIn' | 'signed';
  export interface ReceiptRow {
    label: string;
    value: string;
    /** An address or an ID. */
    mono?: boolean;
  }
</script>

<script lang="ts">
  // The end of an approval with nothing left to copy: what happened, where to go next, and a receipt of what the
  // page knows for certain. No code, no copy button.
  import Icon from '$lib/components/approval/icon.svelte';
  import SpaceNote from '$lib/components/approval/space-note.svelte';
  import { focusHeading } from '$lib/components/approval/focus-heading';
  import CloseTabButton from '$lib/components/ui/close-tab-button.svelte';
  import type { SpaceReadiness } from '$lib/delegate-space-setup';
  import { DONE, fill } from '@openkey/sdk/approval-copy';

  interface Props {
    outcome: DoneOutcome;
    /** The app or command that asked. */
    requester?: string;
    /** Only rows the page knows for certain. */
    rows?: ReceiptRow[];
    spaceNote?: SpaceReadiness | null;
    /** Where the person goes back to. When set, the closing line names it in place of the outcome's line. */
    returnTo?: string;
  }

  let { outcome, requester = '', rows = [], spaceNote = null, returnTo = '' }: Props = $props();

  const words = $derived(DONE[outcome]);
  const said = $derived(outcome === 'approved' || outcome === 'signedIn' || outcome === 'signed');
</script>

<div class="flex w-full flex-col items-center text-center" data-testid={outcome}>
  <div
    class="mt-1 mb-[18px] grid h-[52px] w-[52px] place-items-center rounded-full border {said ? 'border-green-line bg-green-wash text-[#157f3c]' : 'border-surface-300 bg-surface-100 text-surface-500'}"
    aria-hidden="true"
  >
    <Icon name={said ? 'check' : 'x'} class="h-[26px] w-[26px] [stroke-width:2.2]" />
  </div>
  <h1 use:focusHeading class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{words.heading}</h1>
  <p class="m-0 mb-3.5 text-pretty">{returnTo ? fill(DONE.returnTo, { returnTo }) : fill(words.line as string, { requester })}</p>

  {#if spaceNote}
    <div class="mb-3 w-full"><SpaceNote note={spaceNote} /></div>
  {/if}

  {#if rows.length > 0}
    <div class="mt-2 w-full rounded-[14px] border border-surface-200 p-3.5 text-left">
      <dl class="m-0 grid gap-2 text-[13.5px]">
        {#each rows as row (row.label)}
          <div class="flex items-baseline justify-between gap-3.5">
            <dt class="flex-none text-surface-500">{row.label}</dt>
            <dd class="m-0 min-w-0 text-right [overflow-wrap:anywhere] text-surface-950 {row.mono ? 'font-mono text-[12.5px]' : ''}">{row.value}</dd>
          </div>
        {/each}
      </dl>
    </div>
  {/if}

  <CloseTabButton />
</div>
