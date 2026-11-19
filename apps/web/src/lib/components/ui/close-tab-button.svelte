<script lang="ts">
  // A Close button for the pages that end an approval. `window.close()` only works for a
  // window a script opened; when the browser refuses (a tab the owner opened), the button
  // is replaced by a line saying what happened. Focus moves to that line, and it is a
  // status (announced once), not an alert.
  import { browserCloseEnvironment, closeThisTab } from '$lib/delegate-close-tab';

  let { allowBack = false }: { allowBack?: boolean } = $props();

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
  <p bind:this={refusal} tabindex="-1" role="status" class="text-surface-600 text-sm mt-4 outline-none">Your browser kept this tab open. Close it from your browser.</p>
{:else}
  <button
    type="button"
    class="mt-4 rounded-lg border border-surface-200 bg-surface-50 px-4 py-2 text-sm font-medium text-surface-900 hover:bg-surface-100"
    onclick={close}
  >Close</button>
{/if}
