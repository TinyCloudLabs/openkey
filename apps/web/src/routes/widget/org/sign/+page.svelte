<script lang="ts">
  import { page } from '$app/stores';
  import { startAuthentication } from '@simplewebauthn/browser';
  import { api, type OrgKeySignChallenge } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import {
    ORG_SIGN_RESPONSE_TYPE,
    readOrgSignWidgetRequest,
    type OrgSignWidgetRequest,
  } from '$lib/org-sign-widget';
  import { resolveWidgetOrigin } from '$lib/widget-transport';

  // Exact requesting origin from the verified transport; never '*' (TC-690).
  // The server binds this origin into the fresh-passkey challenge (K1 D4.5), so the
  // consent screen and the signature are tied to the page that asked for them.
  const origin = resolveWidgetOrigin($page.url.searchParams.get('origin'));
  // The window that opened this widget: the opener for a popup, otherwise the parent frame.
  const counterparty: Window | null = typeof window === 'undefined'
    ? null
    : window.opener ?? (window.parent !== window ? window.parent : null);

  let request = $state<OrgSignWidgetRequest | null>(null);
  let consent = $state<OrgKeySignChallenge | null>(null);
  let busy = $state(false);
  let finished = $state(false);
  let error = $state('');

  function post(message: Record<string, unknown>) {
    if (origin && counterparty) counterparty.postMessage(message, origin);
  }

  function respondFailure(code: string, message: string) {
    error = message;
    finished = true;
    if (request) {
      post({ type: ORG_SIGN_RESPONSE_TYPE, requestId: request.requestId, ok: false, code, error: message });
    }
  }

  function errorOf(e: unknown): { code: string; message: string } {
    const err = e as { code?: unknown; message?: unknown };
    return {
      code: typeof err?.code === 'string' ? err.code : 'request_failed',
      message: typeof err?.message === 'string' ? err.message : 'Request failed',
    };
  }

  async function prepare(req: OrgSignWidgetRequest) {
    if (!origin) return;
    busy = true;
    try {
      consent = await api.orgKeySignChallenge(req.keyId, { message: req.message, requestingOrigin: origin });
    } catch (e) {
      const { code, message } = errorOf(e);
      respondFailure(code, message);
    } finally {
      busy = false;
    }
  }

  async function approve() {
    if (!origin || !request || !consent || busy) return;
    busy = true;
    error = '';
    try {
      const assertion = await startAuthentication({
        optionsJSON: {
          rpId: consent.rpId,
          challenge: consent.challenge,
          allowCredentials: consent.allowCredentials,
          userVerification: 'required',
        },
      });
      const result = await api.orgKeySign(request.keyId, {
        nonce: consent.nonce,
        message: request.message,
        assertion,
        requestingOrigin: origin,
      });
      finished = true;
      post({
        type: ORG_SIGN_RESPONSE_TYPE,
        requestId: request.requestId,
        ok: true,
        signature: result.signature,
        address: result.address,
      });
    } catch (e) {
      // A cancelled passkey prompt leaves the challenge unconsumed, so the user may retry.
      if ((e as { name?: unknown })?.name === 'NotAllowedError') {
        error = 'Passkey prompt was cancelled. Approve again to retry.';
      } else {
        const { code, message } = errorOf(e);
        respondFailure(code, message);
      }
    } finally {
      busy = false;
    }
  }

  function deny() {
    respondFailure('user_denied', 'Signing was declined');
  }

  // Attach once. Accept only the first request from the exact origin and window.
  $effect(() => {
    if (typeof window === 'undefined') return;
    function handleMessage(event: MessageEvent) {
      if (request || !origin || !counterparty) return;
      const accepted = readOrgSignWidgetRequest(event, origin, counterparty);
      if (!accepted) return;
      request = accepted;
      void prepare(accepted);
    }
    window.addEventListener('message', handleMessage);
    post({ type: 'openkey:ready' });
    return () => window.removeEventListener('message', handleMessage);
  });
</script>

<div class="flex flex-col gap-4 p-4 max-w-md mx-auto">
  <h1 class="text-lg font-semibold">Sign with organization key</h1>

  {#if !origin}
    <Card class="bg-red-500/10 border-red-500 text-red-500 p-4">
      This widget was opened without a valid requesting origin.
    </Card>
  {:else if finished}
    <Card class="p-4">
      {error || 'Done. You can close this window.'}
    </Card>
  {:else if !consent}
    <Card class="p-4">
      {busy ? 'Preparing the statement to sign...' : 'Waiting for a signing request...'}
    </Card>
  {:else}
    <Card class="p-4">
      <span class="block text-surface-400 text-xs uppercase mb-2">Requesting site:</span>
      <span class="font-mono text-sm break-all">{origin}</span>
    </Card>

    <Card class="p-4">
      <span class="block text-surface-400 text-xs uppercase mb-2">You are signing:</span>
      <pre class="m-0 whitespace-pre-wrap break-all font-mono text-xs max-h-[240px] overflow-y-auto">{consent.text}</pre>
    </Card>

    {#if error}
      <Card class="bg-red-500/10 border-red-500 text-red-500 p-4">
        {error}
      </Card>
    {/if}

    <div class="flex gap-2">
      <Button variant="secondary" class="flex-1" onclick={deny} disabled={busy}>Deny</Button>
      <Button class="flex-1" onclick={approve} disabled={busy}>
        {busy ? 'Signing...' : 'Approve with passkey'}
      </Button>
    </div>
  {/if}
</div>
