<script lang="ts">
  import RegistryChangeWidget from '$lib/components/registry/RegistryChangeWidget.svelte';

  let { data }: { data: { embeddedRefusalMessage: string | null } } = $props();
</script>

<RegistryChangeWidget surface="popup" embeddedRefusalMessage={data.embeddedRefusalMessage} />
