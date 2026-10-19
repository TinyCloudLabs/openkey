<script lang="ts">
  // TC-1486: shown INSTEAD of the approval UI when a sign-in (SIWE) message
  // does not name the requesting origin. There is deliberately no approve
  // control and no override: the only action is to close.
  import Button from '$lib/components/ui/button.svelte';

  let { reason, code, onclose }: { reason: string; code: string; onclose: () => void } = $props();
</script>

<div class="flex flex-col gap-4 flex-1" data-testid="siwe-origin-refusal" data-refusal-code={code}>
  <div
    class="bg-red-500/10 border border-red-500 text-red-600 rounded-xl p-4 text-sm flex flex-col gap-2"
    role="alert"
  >
    <p class="font-semibold">OpenKey refused this request</p>
    <p>{reason}</p>
    <p>
      A sign-in message can only be signed for the site that is asking for it. If you
      did not just try to sign in to this site, close this window.
    </p>
  </div>
  <div class="flex gap-3 mt-auto">
    <Button variant="secondary" class="flex-1" onclick={onclose}>Close</Button>
  </div>
</div>
