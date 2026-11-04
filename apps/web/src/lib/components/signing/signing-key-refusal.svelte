<script lang="ts">
  import Button from '$lib/components/ui/button.svelte';

  let { message, requester = null, onreconnect }: {
    message: string;
    requester?: string | null;
    onreconnect: () => void;
  } = $props();
</script>

<section class="flex flex-col gap-4 rounded-2xl border border-surface-200 bg-white p-5 text-surface-900 shadow-sm" role="alert">
  <p class="font-medium">{message}</p>
  <p class="text-sm leading-relaxed text-surface-600">
    Go back to <strong>{requester || 'the requesting app'}</strong> and connect again to choose a key.
  </p>
  <Button class="min-h-11 w-full rounded-xl" onclick={onreconnect}>Back to app</Button>
</section>
