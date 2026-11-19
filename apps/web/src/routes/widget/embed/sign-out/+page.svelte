<script lang="ts">
  import { page } from '$app/stores';
  import { revokeEmbeddedSession } from '$lib/embed-passkey';
  import { resolveWidgetOrigin } from '$lib/widget-transport';
  import { readSignOutWidgetRequest, type SignOutWidgetRequest } from '$lib/sign-out-widget';
  import { api } from '$lib/api';
  import { renewalLeaseCopy } from '$lib/renewal-leases';

  const origin = resolveWidgetOrigin($page.url.searchParams.get('origin'));
  let complete = $state(false);
  let request = $state<SignOutWidgetRequest | null>(null);
  // Whether the account has renewing permissions: only then does the confirm say signing out leaves them on.
  let renewing = $state(false);

  $effect(() => {
    if (!origin) return;
    window.parent.postMessage({ type: 'openkey:ready' }, origin);
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  });

  function onMessage(event: MessageEvent) {
    if (complete || request) return;
    request = readSignOutWidgetRequest(event, origin, window.parent);
    if (request) api.listRenewalLeases().then(({ leases }) => { renewing = leases.length > 0; }, () => {});
  }

  async function confirm() {
    if (!request || !origin || complete) return;
    complete = true;
    const revoked = await revokeEmbeddedSession();
    window.parent.postMessage(
      {
        type: 'openkey:sign-out:response',
        success: true,
        requestId: request.requestId,
        protocolVersion: request.protocolVersion,
        revoked,
      },
      origin,
    );
  }

  function cancel() {
    if (!request || !origin || complete) return;
    complete = true;
    window.parent.postMessage(
      {
        type: 'openkey:sign-out:response',
        success: false,
        requestId: request.requestId,
        protocolVersion: request.protocolVersion,
        error: { code: 'USER_CANCELLED', message: 'User cancelled sign-out' },
      },
      origin,
    );
  }
</script>

<div class="min-h-screen flex items-center justify-center px-6 text-center">
  {#if request}
    <div class="space-y-4">
      <p class="text-sm text-surface-700">Sign out of OpenKey on this device?</p>
      {#if renewing}
        <p class="mx-auto max-w-xs text-xs text-surface-500" data-testid="sign-out-renewal-note">{renewalLeaseCopy.signOutKeepsRenewing} {renewalLeaseCopy.stopRenewalsInSettings}</p>
      {/if}
      <div class="flex justify-center gap-3">
        <button class="rounded-lg bg-surface-900 px-4 py-2 text-sm text-white" onclick={confirm}>Sign out</button>
        <button class="rounded-lg border border-surface-300 px-4 py-2 text-sm text-surface-700" onclick={cancel}>Cancel</button>
      </div>
    </div>
  {:else}
    <span class="text-sm text-surface-500">Preparing sign-out…</span>
  {/if}
</div>
