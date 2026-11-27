<script lang="ts">
  // The one frame every approval page sits in: brand row, account chip, three steps, the page, the footer.
  // Full screen on a phone; a centred card from 600px. The page's own words go in the children.
  import Icon from '$lib/components/approval/icon.svelte';
  import { FRAME, fill } from '@openkey/sdk/approval-copy';
  import type { Snippet } from 'svelte';

  interface Props {
    /** The step that is lit: 0 none, 1 sign in, 2 review, 3 the last step, 4 all three done. */
    at?: 0 | 1 | 2 | 3 | 4;
    /** What the last step says: back to an agent, back to a terminal, or paste a code. */
    last?: 'agent' | 'terminal' | 'code';
    /** The lit step turns red and reads "· stopped". */
    stopped?: boolean;
    /** Centre the page's content (the loader). */
    center?: boolean;
    /** Show the three steps. The Google or Apple window has none. */
    steps?: boolean;
    /** The signed-in account. The chip shows only when this is set. */
    email?: string | null;
    onSignOut?: () => void | Promise<void>;
    children: Snippet;
  }

  let { at = 0, last = 'agent', stopped = false, center = false, steps: showSteps = true, email = null, onSignOut, children }: Props = $props();

  const steps = $derived([FRAME.steps.signIn, FRAME.steps.review, FRAME.steps.last[last]]);
  let menuOpen = $state(false);

  function stepClass(index: number): string {
    const step = index + 1;
    if (at > step) return 'border-surface-950 text-surface-500';
    if (at !== step) return 'border-surface-200 text-surface-400';
    return stopped ? 'border-[#b42318] text-[#b42318]' : 'border-surface-950 text-surface-950';
  }

  function closeMenu(event: MouseEvent | KeyboardEvent) {
    if (!menuOpen) return;
    if (event instanceof KeyboardEvent) {
      if (event.key === 'Escape') menuOpen = false;
      return;
    }
    if (!(event.target as Element | null)?.closest('[data-account-menu]')) menuOpen = false;
  }

  async function signOut() {
    menuOpen = false;
    await onSignOut?.();
  }
</script>

<svelte:window onclick={closeMenu} onkeydown={closeMenu} />

<div class="flex min-h-screen w-full flex-col items-center bg-surface-50 text-[15px] leading-[1.55] text-surface-700 min-[600px]:px-6 min-[600px]:pt-10 min-[600px]:pb-[52px]">
  <div class="flex w-full flex-1 flex-col overflow-hidden bg-white min-[600px]:max-w-[452px] min-[600px]:flex-none min-[600px]:rounded-[18px] min-[600px]:border min-[600px]:border-surface-200 min-[600px]:shadow-[0_1px_2px_rgba(15,17,21,0.04),0_18px_40px_-22px_rgba(15,17,21,0.18)]">
    <header class="flex items-center justify-between gap-3 px-5 pt-[14px] pb-[13px] min-[600px]:px-7 min-[600px]:pt-4 min-[600px]:pb-[14px]">
      <span class="inline-flex items-center gap-[9px] text-[15px] font-semibold tracking-[-0.01em] text-surface-950">
        <span class="grid h-[26px] w-[26px] flex-none place-items-center rounded-lg bg-linear-to-br from-surface-800 to-surface-950 text-white">
          <Icon name="key" class="h-[15px] w-[15px]" />
        </span>
        {FRAME.brand}
      </span>
      {#if email}
        <div class="relative min-w-0" data-account-menu>
          <button
            type="button"
            class="inline-flex max-w-full min-w-0 items-center gap-[7px] rounded-full border border-surface-200 bg-white py-[3px] pr-[10px] pl-1 text-[12.5px] text-surface-700"
            aria-expanded={menuOpen}
            aria-controls="approval-account-menu"
            onclick={() => (menuOpen = !menuOpen)}
          >
            <span class="grid h-5 w-5 flex-none place-items-center rounded-full bg-surface-100 text-[10.5px] font-semibold text-surface-950" aria-hidden="true">{email.charAt(0).toUpperCase()}</span>
            <span class="min-w-0 truncate">{email}</span>
            <Icon name="chev" class="h-3 w-3 text-surface-400" />
          </button>
          {#if menuOpen}
            <div id="approval-account-menu" class="absolute right-0 z-10 mt-1.5 min-w-full rounded-xl border border-surface-200 bg-white p-1 shadow-lg">
              <button
                type="button"
                class="block w-full rounded-lg px-3 py-2 text-left text-[13.5px] font-medium whitespace-nowrap text-surface-950 hover:bg-surface-50"
                onclick={signOut}
              >{FRAME.signOut}</button>
            </div>
          {/if}
        </div>
      {/if}
    </header>

    {#if showSteps}
      <ol class="m-0 grid list-none grid-cols-3 gap-1.5 p-0 px-5 min-[600px]:px-7" aria-label={FRAME.progress}>
        {#each steps as label, index (index)}
          <li
            class="border-t-2 pt-[7px] text-[11.5px] font-semibold whitespace-nowrap {stepClass(index)}"
            aria-current={at === index + 1 ? 'step' : undefined}
          >{stopped && at === index + 1 ? fill(FRAME.stopped, { step: label }) : label}</li>
        {/each}
      </ol>
    {/if}

    <main class="flex flex-1 flex-col px-5 pt-[26px] pb-6 min-[600px]:px-7 min-[600px]:pt-[30px] min-[600px]:pb-7 {center ? 'items-center text-center' : ''}">
      {@render children()}
    </main>

    <footer class="flex items-center justify-center gap-2 border-t border-surface-200 px-5 pt-[14px] pb-[18px] text-center text-xs text-surface-500 min-[600px]:px-7 min-[600px]:pb-4">
      <Icon name="shield" class="h-[14px] w-[14px]" />
      <span>{FRAME.footer}</span>
    </footer>
  </div>
</div>
