<script lang="ts">
  // The embedded hand-off for account setup. It shows one button and nothing else: no record, no requester and no
  // approve control, so a page that frames it can at most open OpenKey's own account setup window. Until the setup is
  // built, the button is the way to TinyCloud One and the app is answered ACCOUNT_SETUP_UNAVAILABLE.
  import { page } from '$app/stores';
  import Button from '$lib/components/ui/button.svelte';
  import { resolveWidgetOrigin } from '$lib/widget-transport';
  import {
    accountSetupFailure,
    readAccountSetupRequest,
    TINYCLOUD_ONE_SETUP_URL,
    type AccountSetupRequest,
  } from '$lib/account-setup';

  const origin = resolveWidgetOrigin($page.url.searchParams.get('origin'));
  const parentWindow: Window | null = typeof window !== 'undefined' && window.parent !== window ? window.parent : null;

  let request = $state<AccountSetupRequest | null>(null);
  let answered = false;

  $effect(() => {
    if (!parentWindow || !origin) return;
    window.addEventListener('message', onMessage);
    parentWindow.postMessage({ type: 'openkey:ready' }, origin);
    return () => window.removeEventListener('message', onMessage);
  });

  function onMessage(event: MessageEvent) {
    if (request) return;
    request = readAccountSetupRequest(event, origin, parentWindow, false);
  }

  function finishSetup() {
    if (!request || answered || !parentWindow || !origin) return;
    answered = true;
    parentWindow.postMessage(
      accountSetupFailure(request, 'ACCOUNT_SETUP_UNAVAILABLE', "Account setup isn't available here."),
      origin,
    );
  }
</script>

<div class="flex flex-col gap-4 bg-[#fafafa] p-4 rounded-2xl">
  <p class="text-sm text-surface-700">Your TinyCloud account needs one more step before this app can use it.</p>
  <Button href={TINYCLOUD_ONE_SETUP_URL} target="_blank" rel="noopener" onclick={finishSetup} disabled={!request} class="w-full rounded-xl">
    Finish setup
  </Button>
</div>
