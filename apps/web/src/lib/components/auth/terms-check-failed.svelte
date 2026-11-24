<script lang="ts">
  import Button from '$lib/components/ui/button.svelte';

  // Whether the account has agreed to the Terms could not be read. Nothing behind it is shown until a check succeeds.
  let { onretry, compact = false }: { onretry: () => void; compact?: boolean } = $props();
</script>

<div
  class={compact
    ? 'flex flex-col items-center py-4 text-center'
    : 'flex min-h-screen flex-col items-center justify-center bg-surface-50 px-4 py-12 text-center'}
  data-testid="terms-check-failed"
>
  <p class="mb-4 text-sm text-surface-700" role="alert">Couldn’t check whether you’ve agreed to the Terms.</p>
  <Button onclick={onretry} class="rounded-xl">Try again</Button>
</div>
