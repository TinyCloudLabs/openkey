<script lang="ts">
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  // After declining the Terms: signed out, nothing deleted.
  let { signInHref = '/auth/login', onsignin }: { signInHref?: string; onsignin?: () => void } = $props();
</script>

<div class="flex min-h-screen items-center justify-center bg-surface-50 px-4 py-12">
  <Card class="w-full max-w-md p-8 text-center sm:p-10" data-testid="terms-result">
    <h1 class="mb-2 text-2xl font-bold text-surface-900">You’re signed out</h1>
    <p class="mb-7 text-sm text-surface-500">To use OpenKey again, sign in and agree to the Terms of Service.</p>
    {#if onsignin}
      <Button onclick={onsignin} class="w-full">Sign in</Button>
    {:else}
      <Button href={signInHref} class="w-full">Sign in</Button>
    {/if}
  </Card>
</div>
