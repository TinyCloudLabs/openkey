<script lang="ts">
  // OpenKey's own account setup page. Unframeable (frame-policy.ts): it runs in its own window, opened by the app, by
  // the embedded hand-off, or by the connect window navigating itself here. Until the setup is built, it shows the
  // card and the way to TinyCloud One, and answers the app ACCOUNT_SETUP_UNAVAILABLE.
  import { page } from '$app/stores';
  import Card from '$lib/components/ui/card.svelte';
  import Button from '$lib/components/ui/button.svelte';
  import { resolveWidgetOrigin } from '$lib/widget-transport';
  import {
    accountSetupFailure,
    readAccountSetupRequest,
    TINYCLOUD_ONE_SETUP_URL,
    type AccountSetupRequest,
    type AccountSetupResponse,
  } from '$lib/account-setup';

  const relayed = $page.url.searchParams.get('via') === 'embed';
  const counterpartyOrigin = relayed
    ? (typeof window === 'undefined' ? null : window.location.origin)
    : resolveWidgetOrigin($page.url.searchParams.get('origin'));
  const counterparty: Window | null = typeof window === 'undefined' ? null : window.opener;

  let request = $state<AccountSetupRequest | null>(null);
  let answered = $state(false);

  $effect(() => {
    if (!counterparty || !counterpartyOrigin) return;
    window.addEventListener('message', onMessage);
    counterparty.postMessage({ type: 'openkey:ready' }, counterpartyOrigin);
    return () => window.removeEventListener('message', onMessage);
  });

  function onMessage(event: MessageEvent) {
    if (request) return;
    request = readAccountSetupRequest(event, counterpartyOrigin, counterparty, relayed);
  }

  function answer(response: AccountSetupResponse) {
    if (answered || !counterparty || !counterpartyOrigin) return;
    answered = true;
    counterparty.postMessage(response, counterpartyOrigin);
  }

  function cancel() {
    if (request) answer(accountSetupFailure(request, 'USER_CANCELLED', 'The owner closed account setup.'));
    window.close();
  }

  function unavailable() {
    if (request) answer(accountSetupFailure(request, 'ACCOUNT_SETUP_UNAVAILABLE', "Account setup isn't available here."));
  }
</script>

<div class="min-h-screen bg-[#fafafa] flex flex-col items-center justify-center px-4 py-8">
  <Card class="w-full max-w-[440px]">
    <h1 class="text-lg font-semibold text-surface-900">Set up your TinyCloud account</h1>
    {#if request}
      <p class="mt-3 text-sm text-surface-600">
        Account setup isn't available here. Finish setup in TinyCloud One.
      </p>
      <div class="mt-5 flex flex-col gap-3">
        <Button href={TINYCLOUD_ONE_SETUP_URL} target="_blank" rel="noopener" onclick={unavailable} class="w-full rounded-xl">
          Open TinyCloud One
        </Button>
        <Button variant="secondary" onclick={cancel} class="w-full rounded-xl">Cancel</Button>
      </div>
    {:else}
      <p class="mt-3 text-sm text-surface-500">Waiting for the app…</p>
    {/if}
  </Card>
</div>
