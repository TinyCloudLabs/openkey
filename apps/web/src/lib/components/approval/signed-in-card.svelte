<script lang="ts">
  // Prepared sign-in and revoke: the person signed in inside this tab. The one-use request is read only
  // when they press the button, never as a side effect of signing in.
  import { focusHeading } from '$lib/components/approval/focus-heading';
  import Button from '$lib/components/ui/button.svelte';
  import { SIGN_IN } from '@openkey/sdk/approval-copy';

  let { onReview, onCancel }: { onReview: () => void; onCancel: () => void } = $props();
</script>

<p class="m-0 mb-2.5 text-[11.5px] font-semibold tracking-[0.09em] text-surface-500 uppercase">{SIGN_IN.eyebrow}</p>
<h1 use:focusHeading class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{SIGN_IN.signedIn.heading}</h1>
<p class="m-0 mb-3.5 text-pretty">{SIGN_IN.signedIn.line}</p>
<div class="mt-5 grid gap-2.5">
  <Button class="w-full" onclick={onReview}>{SIGN_IN.signedIn.review}</Button>
  <Button variant="ghost" class="w-full" onclick={onCancel}>{SIGN_IN.signedIn.cancel}</Button>
</div>
