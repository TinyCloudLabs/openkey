<script lang="ts">
  import { onMount } from 'svelte';
  import { API_BASE } from '$lib/auth-client';
  import { DELETE_ACCOUNT_PATH, loadDeletionSupport } from '$lib/account-deletion';

  // Delete your account, on the Terms' Other options and Disconnect apps pages. Like Settings, it shows
  // only once the API answers with the deletion step-up (TC-1231).
  let supported = $state(false);

  onMount(() => {
    void loadDeletionSupport(API_BASE).then((support) => { supported = support.supported; }).catch(() => {});
  });
</script>

{#if supported}
  <section class="mt-6" aria-labelledby="terms-delete-heading" data-testid="terms-delete-account">
    <h2 id="terms-delete-heading" class="text-sm font-semibold text-surface-900">Delete your account</h2>
    <p class="mt-1 text-sm text-surface-500">Deletes your OpenKey account and its keys. This can’t be undone.</p>
    <a
      href={DELETE_ACCOUNT_PATH}
      class="mt-3 flex h-10 w-full items-center justify-center rounded-full border border-red-300 bg-white px-4 text-sm font-semibold text-red-700 no-underline transition-colors hover:border-red-500 hover:bg-red-50"
    >
      Delete account…
    </a>
  </section>
{/if}
