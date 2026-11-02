<script lang="ts">
  import { page } from '$app/stores';
  import Delegate from '../../delegate/+page.svelte';
</script>

{#key $page.params.id}
  <Delegate />
{/key}
