<script lang="ts">
  import { page } from '$app/stores';
  import OrgKeyAdmins from '$lib/components/OrgKeyAdmins.svelte';
</script>
{#key $page.params.id}<OrgKeyAdmins invitationId={$page.params.id} />{/key}
