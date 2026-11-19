<script lang="ts">
  import { onMount } from 'svelte';
  import { API_BASE } from '$lib/auth-client';
  import { DELETE_ACCOUNT_PATH, loadDeletionSupport } from '$lib/account-deletion';
  import Card from '$lib/components/ui/card.svelte';

  // Hidden until the API answers with the deletion step-up contract (TC-1231):
  // the web app deploys before the API, and an older API can't delete a
  // passkey-less account.
  let supported = $state(false);

  onMount(() => {
    void loadDeletionSupport(API_BASE).then((support) => { supported = support.supported; }).catch(() => {});
  });
</script>

{#if supported}
  <Card id="delete-account" class="mt-6 border-red-200">
    <div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
      <div class="max-w-xl">
        <h2 class="text-xl font-semibold text-surface-900">Delete account</h2>
        <p class="mt-1 text-sm text-surface-500">
          Permanently delete your OpenKey account and destroy its keys. This can't be undone.
        </p>
      </div>
      <a
        href={DELETE_ACCOUNT_PATH}
        class="inline-flex h-10 shrink-0 items-center justify-center rounded-full border border-red-300 bg-white px-4 text-sm font-semibold text-red-700 transition-colors hover:border-red-500 hover:bg-red-50"
      >
        Delete account
      </a>
    </div>
  </Card>
{/if}
