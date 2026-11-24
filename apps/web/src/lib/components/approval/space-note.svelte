<script lang="ts">
  // How the app's TinyCloud space came out after approving. "Ready" is a plain line; the rest sit in a quiet
  // box that is read out once. A failed setup keeps the server's reason in a fold.
  import Icon from '$lib/components/approval/icon.svelte';
  import type { SpaceReadiness } from '$lib/delegate-space-setup';
  import { DONE } from '@openkey/sdk/approval-copy';

  let { note }: { note: SpaceReadiness } = $props();
</script>

{#if note.kind === 'ready'}
  <p class="m-0 mt-3.5 w-full text-left text-[13px] leading-normal text-surface-500" role="status">{note.text}</p>
{:else}
  <div role="status" class="mt-3.5 grid w-full grid-cols-[16px_1fr] gap-[9px] rounded-[11px] border border-surface-200 bg-surface-50 px-3 py-[9px] text-left text-[13.5px] leading-[1.45] text-surface-700">
    <Icon name="alert" class="mt-0.5 h-4 w-4" />
    <div class="min-w-0">
      <p class="m-0">{note.text}</p>
      {#if note.detail}
        <details class="mt-2">
          <summary class="cursor-pointer font-medium">{DONE.spaceNote.details}</summary>
          <pre class="mt-2 text-xs break-words whitespace-pre-wrap">{note.detail}</pre>
        </details>
      {/if}
    </div>
  </div>
{/if}
