<script>
  // Props: show (boolean). The copy lives here; the page decides when to show it.
  let { show } = $props();
</script>

{#if show}
  <p class="text-surface-500 text-sm" role="status">
    Your browser may ask to connect to devices on your network: choose Allow to finish in your terminal. If it doesn't finish, a code will appear here to enter in your terminal.
  </p>
{/if}
