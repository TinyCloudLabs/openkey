<script lang="ts">
  import { page } from '$app/stores';
  import OrgKeyAdmins from '$lib/components/OrgKeyAdmins.svelte';
</script>
{#key $page.params.keyId}<OrgKeyAdmins keyId={$page.params.keyId} />{/key}
