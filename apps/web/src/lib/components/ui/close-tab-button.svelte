<script lang="ts">
  // "Close this tab" for the pages that end an approval. `window.close()` only works for a
  // window a script opened; when the browser refuses (a tab the owner opened), the button
  // is replaced by a line saying what happened. Focus moves to that line, and it is a
  // status (announced once), not an alert.
  import Button from '$lib/components/ui/button.svelte';
  import { browserCloseEnvironment, closeThisTab } from '$lib/delegate-close-tab';
  import { CLOSE_TAB, TAB_KEPT_OPEN } from '@openkey/sdk/approval-copy';

  interface Props {
    allowBack?: boolean;
    /** `button`: the page's main button. `link`: a quiet link in a line of links. */
    look?: 'button' | 'link';
    secondary?: boolean;
    class?: string;
  }

  let { allowBack = false, look = 'button', secondary = false, class: className = 'mt-5 w-full' }: Props = $props();

  let stuck = $state(false);
  let refusal = $state<HTMLParagraphElement | null>(null);
  let cancelPending: (() => void) | null = null;

  // A pending check is cancelled when the page is destroyed.
  $effect(() => () => cancelPending?.());

  $effect(() => {
    if (stuck) refusal?.focus();
  });

  function close() {
    cancelPending?.();
    cancelPending = closeThisTab(browserCloseEnvironment(), () => { stuck = true; }, { allowBack });
  }
</script>

{#if stuck}
  <p bind:this={refusal} tabindex="-1" role="status" class="m-0 text-[13px] leading-normal text-surface-500 outline-none {look === 'button' ? 'mt-4' : ''}">{TAB_KEPT_OPEN}</p>
{:else if look === 'link'}
  <button
    type="button"
    class="cursor-pointer border-0 bg-transparent p-0 font-semibold text-surface-950 underline decoration-surface-300 underline-offset-[3px]"
    onclick={close}
  >{CLOSE_TAB}</button>
{:else}
  <Button class={className} variant={secondary ? 'secondary' : 'default'} onclick={close}>{CLOSE_TAB}</Button>
{/if}
