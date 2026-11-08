<script lang="ts">
  import Button from '$lib/components/ui/button.svelte';

  let { message, requester = null, onreconnect, onsignout, onretry }: {
    message: string;
    requester?: string | null;
    onreconnect: () => void;
    /** No key of this account fits: signing in to another account continues the same request. */
    onsignout?: () => void;
    /** The key or key list could not be read: reading it again may work. */
    onretry?: () => void;
  } = $props();

  // Transport errors retain reconnect guidance; this surface renders it once below.
  const reason = $derived(message.replace(/ Reconnect to choose a key\.$/, ''));
  const recovers = $derived(!!onsignout || !!onretry);
</script>

<section class="flex flex-col gap-4 rounded-2xl border border-surface-200 bg-white p-5 text-surface-900 shadow-sm" role="alert" data-testid="signing-key-refusal">
  <p class="font-medium">{reason}</p>
  <p class="text-sm leading-relaxed text-surface-600">
    Go back to <strong>{requester || 'the requesting app'}</strong> and connect again to choose a key.
  </p>
  {#if onsignout}
    <Button class="min-h-11 w-full rounded-xl" data-testid="signing-key-sign-out" onclick={onsignout}>Sign out</Button>
  {:else if onretry}
    <Button class="min-h-11 w-full rounded-xl" data-testid="signing-key-retry" onclick={onretry}>Try again</Button>
  {/if}
  <Button
    variant={recovers ? 'secondary' : 'default'}
    class="min-h-11 w-full rounded-xl"
    data-testid="signing-key-back"
    onclick={onreconnect}
  >Back to app</Button>
</section>
