<script lang="ts">
  // Shown by the sign widgets in place of the approval when the API refuses a host message because the owner's
  // TinyCloud account is not set up. The tap opens OpenKey's own account setup window; once the account is set up the
  // widget prepares the request a second time.
  import Button from '$lib/components/ui/button.svelte';
  import { openAccountSetupWindow, TINYCLOUD_ONE_SETUP_URL } from '$lib/account-setup';

  let {
    keyId,
    requestOrigin,
    ondone,
    oncancel,
  }: {
    keyId: string;
    /** The app this widget verified; the setup window names it to the owner. */
    requestOrigin: string;
    ondone: (outcome: 'published' | 'present') => void;
    oncancel: () => void;
  } = $props();

  let open = $state(false);
  let notice = $state<string | null>(null);
  let setupUrl = $state<string | null>(null);

  function finishSetup() {
    if (open) return;
    open = true;
    notice = null;
    setupUrl = null;
    openAccountSetupWindow({ keyId, requestOrigin }).then((result) => {
      open = false;
      if (result.success) {
        ondone(result.outcome);
        return;
      }
      if (result.error.code === 'USER_CANCELLED') return;
      notice = result.error.message;
      setupUrl = result.error.setupUrl ?? null;
    });
  }
</script>

<div class="flex flex-col gap-4 flex-1" data-testid="account-setup-card">
  <div class="rounded-xl border border-surface-200 bg-surface-50 p-4 text-sm text-surface-700 flex flex-col gap-2">
    <p class="font-semibold text-surface-900">Finish setting up your TinyCloud account</p>
    <p>Your TinyCloud account needs one more step before this app can use it. OpenKey opens a window to finish setup.</p>
  </div>
  {#if notice}
    <p class="text-sm text-red-700" role="alert">
      {notice}
      {#if setupUrl}
        <a class="underline" href={TINYCLOUD_ONE_SETUP_URL} target="_blank" rel="noopener">Open TinyCloud One</a>
      {/if}
    </p>
  {/if}
  <div class="flex gap-3 mt-auto">
    <Button variant="secondary" class="flex-1" onclick={oncancel}>Cancel</Button>
    <Button class="flex-1" onclick={finishSetup} disabled={open} data-testid="account-setup-finish">
      {open ? 'Finishing setup…' : 'Finish setup'}
    </Button>
  </div>
</div>
