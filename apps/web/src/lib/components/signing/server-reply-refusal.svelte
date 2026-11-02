<script lang="ts">
  // Shown instead of the approval UI when the server's reply to prepare,
  // preview or sign cannot be read. Nothing was approved. The HTTP status is in
  // Advanced details only, never the reply itself.
  import Button from '$lib/components/ui/button.svelte';
  import { SERVER_REPLY_BODY, SERVER_REPLY_TITLE } from '$lib/server-reply';

  let { status, onclose }: { status: number; onclose: () => void } = $props();
</script>

<div class="flex flex-col gap-4 flex-1" data-testid="server-reply-refusal">
  <div
    class="bg-red-500/10 border border-red-500 text-red-600 rounded-xl p-4 text-sm flex flex-col gap-2"
    role="alert"
  >
    <p class="font-semibold">{SERVER_REPLY_TITLE}</p>
    <p>{SERVER_REPLY_BODY}</p>
  </div>
  <details class="text-sm text-surface-700">
    <summary class="cursor-pointer">Advanced details</summary>
    <div class="row flex gap-2 pt-2">
      <span class="label">Server reply</span>
      <span class="value mono">HTTP {status}</span>
    </div>
  </details>
  <div class="flex gap-3 mt-auto">
    <Button variant="secondary" class="flex-1" onclick={onclose}>Close</Button>
  </div>
</div>
