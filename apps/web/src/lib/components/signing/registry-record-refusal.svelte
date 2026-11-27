<script lang="ts">
  // Hardening: registry record signing. Shown INSTEAD of the approval UI: there is no approve control and no
  // override, only a way back (embed) or a way to close (popup).
  import { REGISTRY_RECORD_SIGN_REFUSED } from '@openkey/capability-review';
  import Button from '$lib/components/ui/button.svelte';

  let { variant, onclose }: { variant: 'embed' | 'popup'; onclose: () => void } = $props();
</script>

<div
  class="flex flex-col gap-4 flex-1"
  data-testid="registry-record-refusal"
  data-refusal-code={REGISTRY_RECORD_SIGN_REFUSED.code}
>
  <div
    class="bg-red-500/10 border border-red-500 text-red-600 rounded-xl p-4 text-sm flex flex-col gap-2"
    role="alert"
  >
    <p class="font-semibold">{REGISTRY_RECORD_SIGN_REFUSED.title}</p>
    <p>{variant === 'embed' ? REGISTRY_RECORD_SIGN_REFUSED.embedBody : REGISTRY_RECORD_SIGN_REFUSED.popupBody}</p>
  </div>
  <div class="flex gap-3 mt-auto">
    <Button variant="secondary" class="flex-1" onclick={onclose}>
      {variant === 'embed' ? REGISTRY_RECORD_SIGN_REFUSED.embedButton : REGISTRY_RECORD_SIGN_REFUSED.popupButton}
    </Button>
  </div>
</div>
