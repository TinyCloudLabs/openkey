<script>
  // Props: show (boolean). The copy lives here; the page decides when to show it.
  let { show } = $props();
</script>

{#if show}
  <p class="text-surface-500 text-sm" role="status">
    Your browser may ask to connect to devices on your local network. Choose Allow to finish in your terminal. If it doesn't finish, a code will appear here for you to enter in your terminal.
  </p>
{/if}
