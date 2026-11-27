<script lang="ts">
  // The embedded hand-off for account setup. It shows one button and nothing else: no record and no approve control,
  // so a page that frames it can at most open OpenKey's own account setup window. The owner's tap opens that window;
  // the hand-off tells it the app this frame verified and relays its answer to the app.
  import { page } from '$app/stores';
  import Button from '$lib/components/ui/button.svelte';
  import { isFromWidgetCounterparty, resolveWidgetOrigin } from '$lib/widget-transport';
  import {
    accountSetupAnswer,
    accountSetupFailure,
    openAccountSetupWindow,
    readAccountSetupRequest,
    type AccountSetupRequest,
  } from '$lib/account-setup';

  const origin = resolveWidgetOrigin($page.url.searchParams.get('origin'));
  const parentWindow: Window | null = typeof window !== 'undefined' && window.parent !== window ? window.parent : null;

  let request = $state<AccountSetupRequest | null>(null);
  let open = $state(false);
  let notice = $state<string | null>(null);
  let answered = false;

  $effect(() => {
    if (!parentWindow || !origin) return;
    window.addEventListener('message', onMessage);
    parentWindow.postMessage({ type: 'openkey:ready' }, origin);
    return () => window.removeEventListener('message', onMessage);
  });

  function onMessage(event: MessageEvent) {
    if (request) return;
    if (!isFromWidgetCounterparty(event, origin, parentWindow)) return;
    request = readAccountSetupRequest(event, origin, parentWindow, false);
  }

  function finishSetup() {
    if (!request || answered || open || !parentWindow || !origin) return;
    const current = request;
    open = true;
    notice = null;
    openAccountSetupWindow({ keyId: current.keyId, requestOrigin: current.requester }).then((result) => {
      open = false;
      if (!result.success && result.error.code === 'POPUP_BLOCKED') {
        notice = result.error.message;
        return;
      }
      if (answered) return;
      answered = true;
      parentWindow.postMessage(accountSetupAnswer(current, result), origin);
    });
  }

  function cancel() {
    if (!request || answered || !parentWindow || !origin) return;
    answered = true;
    parentWindow.postMessage(accountSetupFailure(request, 'USER_CANCELLED', 'The owner closed account setup.'), origin);
  }
</script>

<div class="flex flex-col gap-4 bg-[#fafafa] p-4 rounded-2xl" data-testid="account-setup-handoff">
  <p class="text-sm text-surface-700">Your TinyCloud account needs one more step before this app can use it.</p>
  <Button onclick={finishSetup} disabled={!request || open} class="w-full rounded-xl" data-testid="account-setup-finish">
    {open ? 'Finishing setup in the OpenKey window…' : 'Finish setup'}
  </Button>
  <Button variant="secondary" onclick={cancel} disabled={!request} class="w-full rounded-xl">Cancel</Button>
  {#if notice}
    <p class="text-sm text-red-700" role="alert">{notice}</p>
  {/if}
</div>
