<script lang="ts">
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { parseSIWE } from '$lib/siwe-parser';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import SiweMessage from '$lib/components/ui/siwe-message.svelte';
  import SigningApproval from '$lib/components/signing/signing-approval.svelte';
  import {
    parseCapabilityReview,
    defaultSelection,
    type CapabilityReviewModel,
  } from '@openkey/capability-review';
  import {
    createWidgetTransport,
    type WidgetRequest,
    type WidgetTransport,
  } from '$lib/widget-transport';

  const session = authClient.useSession();

  let message = $state('');
  let messageProtocolVersion = $state<number | null>(null);
  // The JWK carried by a versioned sign request. Required by the
  // /authorize-sign endpoint to regenerate a narrowed SIWE bound to the
  // same session key. Legacy requests do not include this.
  let messageJwk = $state<Record<string, unknown> | null>(null);
  // Sol MAJOR-2: the TinyCloud host the resulting session will activate
  // against. Forwarded to /authorize-sign-prepare so the server binds it
  // and /authorize-sign cannot swap hosts.
  let messageHost = $state<string>('');
  let keyId = $state<string | null>(null);
  let key = $state<EthereumKey | null>(null);
  let loading = $state(true);
  let signing = $state(false);
  let error = $state('');
  let sessionChecked = $state(false);
  // When a versioned request comes in through the shared transport, we
  // remember the correlated requestId so the response echoes it. Legacy
  // path (compat) does not carry a requestId — it uses direct postMessage.
  let currentRequestId = $state<string | null>(null);
  let transport: WidgetTransport | null = null;

  // Shared capability-review state — the SigningApproval component uses this
  // when the request looks like a TinyCloud SIWE-ReCap. Legacy plain
  // signMessage requests still render via the legacy fallback below.
  let reviewModel = $state<CapabilityReviewModel | null>(null);
  let reviewSelection = $state(new Set<string>());
  let reviewEditing = $state(false);

  // Rawquery-string origin. Legacy: any origin ever accepted; the widget
  // used '*' as a fallback. New default: we still surface '*' here for
  // backward compatibility with popups where the parent origin was unknown,
  // but STRICT origin AND source validation happens on the message ingress
  // path (Sol MAJOR-4). Versioned callers (protocolVersion >= 1) MUST use
  // a real origin — '*' is refused for editing/rewriting flows.
  const origin = $page.url.searchParams.get('origin') || '*';

  // Use $effect instead of onMount for Svelte 5 compatibility with SSR disabled
  // onMount doesn't fire when ssr=false in SvelteKit, but $effect does
  let initialized = $state(false);

  $effect(() => {
    if (typeof window !== 'undefined' && !initialized) {
      initialized = true;

      // Sol continuation contract: use the shared widget transport for
      // real origins (versioned protocol). Compatibility path for '*'
      // origin is intentionally restricted to read-only exact-byte
      // signing and uses direct postMessage.
      if (origin !== '*') {
        try {
          const container = window.opener ? 'popup' : 'iframe';
          transport = createWidgetTransport({
            origin,
            container,
            onRequest: handleTransportRequest,
            onClose: handleTransportClose,
            onInvalid: (reason, event) => {
              console.warn('[sign widget] invalid message:', reason, event.origin);
            },
          });
          transport.emitReady();
        } catch (e) {
          console.warn('[sign widget] transport init failed:', e);
        }
      }

      // Legacy compatibility: unversioned direct postMessage listener.
      // Only used by the '*' origin path (read-only exact-byte signing)
      // and by pre-consolidation SDKs that don't yet include requestId.
      window.addEventListener('message', handleMessage);

      // Legacy ready message for pre-consolidation SDKs that listen for
      // the unversioned envelope. Only emit under the wildcard-origin
      // compatibility path — versioned callers get the transport's ready.
      if (origin === '*') {
        const targetOrigin = new URL(window.location.href).searchParams.get('origin') || '*';
        if (window.opener) {
          window.opener.postMessage({ type: 'openkey:ready' }, targetOrigin);
        } else if (window.parent !== window) {
          window.parent.postMessage({ type: 'openkey:ready' }, targetOrigin);
        }
      }
    }
  });

  // Cleanup transport when the component unmounts.
  $effect(() => {
    return () => {
      transport?.destroy();
      transport = null;
    };
  });

  function handleTransportRequest(request: WidgetRequest) {
    console.log('[sign widget] transport request:', request.requestId);
    const data = request.data;
    currentRequestId = request.requestId;
    message = String(data.message ?? '');
    messageProtocolVersion = request.protocolVersion;
    messageJwk = (data.jwk as Record<string, unknown>) ?? null;
    messageHost = typeof data.host === 'string' ? data.host : '';
    keyId = typeof data.keyId === 'string' ? data.keyId : null;
    keyFetched = false;
  }

  function handleTransportClose() {
    console.log('[sign widget] transport close');
    // Nothing to do — the parent already closed us.
  }

  // Reactively update loading state when session becomes available
  $effect(() => {
    if ($session.data && !sessionChecked) {
      sessionChecked = true;
      loading = false;
    }
  });

  // Reactively fetch key when session becomes available and we have a keyId
  let keyFetched = $state(false);
  $effect(() => {
    if ($session.data && keyId && !keyFetched && !key) {
      keyFetched = true;
      api.getKey(keyId).then(result => {
        key = result.key;
      }).catch(() => {
        // Key not found
      });
    }
  });

  async function handleMessage(event: MessageEvent) {
    // Sol continuation contract: versioned messages are handled by the
    // shared transport (when a real origin is present). Under the '*'
    // origin compatibility path, we accept ONLY unversioned messages and
    // only for read-only exact-byte signing.
    const incomingProtocolVersion =
      typeof event.data?.protocolVersion === 'number' ? event.data.protocolVersion : null;
    const incomingRequestId =
      typeof event.data?.requestId === 'string' ? event.data.requestId : null;

    if (origin === '*') {
      // Refuse any versioned request under wildcard origin.
      if (incomingProtocolVersion !== null && incomingProtocolVersion >= 1) {
        console.warn('[sign widget] refusing versioned request with wildcard origin');
        return;
      }
      // Even under '*' we MUST verify the source is a legitimate parent.
      if (event.source !== window.opener && event.source !== window.parent) {
        return;
      }
    } else {
      // Real origin: skip versioned requests here — the transport handles
      // them. Only handle legacy unversioned requests as a compatibility
      // shim for pre-consolidation SDKs.
      if (incomingProtocolVersion !== null && incomingProtocolVersion >= 1 && incomingRequestId) {
        return;
      }
      if (event.origin !== origin) return;
      if (event.source !== window.opener && event.source !== window.parent) return;
    }

    console.log('[sign widget] received message:', event.data?.type, event.data);
    if (event.data?.type === 'openkey:sign:request') {
      console.log('[sign widget] sign request received, message:', event.data.message?.substring(0, 100), 'keyId:', event.data.keyId);
      message = event.data.message;
      messageProtocolVersion = incomingProtocolVersion;
      messageJwk = event.data.jwk ?? null;
      messageHost = typeof event.data.host === 'string' ? event.data.host : '';
      keyId = event.data.keyId || null;
      keyFetched = false; // Reset so effect can run

      // Try immediately if session is already available
      if (keyId && $session.data) {
        try {
          const result = await api.getKey(keyId);
          key = result.key;
          keyFetched = true;
        } catch {
          // Key not found, will prompt user to select
        }
      }
      // The reviewModel is built by a $effect below that reacts to
      // `message` AND `key` — this fixes the Sol MAJOR-8 bug where the
      // model was created with a placeholder zero-address before the key
      // loaded, leaving the review UI displaying wrong signer info.
    }
  }

  // Build the capability-review model reactively. Only run once BOTH
  // `message` and `key` are available so the signer address in the model
  // reflects the real key rather than a zero-address placeholder.
  $effect(() => {
    if (!message || !key) {
      // Do not construct a model with a placeholder key. Legacy fallback
      // rendering will show a spinner or "Please connect" until the key
      // loads and this effect fires again.
      reviewModel = null;
      return;
    }
    const canEdit =
      messageProtocolVersion !== null &&
      messageProtocolVersion >= 1 &&
      origin !== '*';
    try {
      const model = parseCapabilityReview({
        message,
        signer: {
          label: 'Selected key',
          address: key.address,
          chainId: 1,
          provenance: key.keyType === 'EXTERNAL' ? 'external' : 'managed',
        },
        editable: canEdit,
        metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' },
        reason: { text: '', source: 'none' },
        requester: {
          displayName: origin === '*' ? 'Unknown origin' : origin,
          verifiedOrigin: origin === '*' ? null : origin,
          manifestId: null,
          manifestDigest: null,
          domainWarning: false,
          originWarning: false,
        },
      });
      reviewModel = model;
      reviewSelection = defaultSelection(model);
    } catch {
      reviewModel = null;
    }
  });

  async function signMessage() {
    if (!key || !message) return;

    signing = true;
    error = '';

    try {
      // Sol CRITICAL-1: for editable TinyCloud requests (versioned
      // protocol + real origin + ReCap SIWE), route through the
      // server-authoritative /api/delegate/authorize-sign endpoint. The
      // server regenerates a narrowed SIWE from the current selection
      // and signs THOSE bytes — the widget never returns `signedMessage`
      // that differs from what the signature verifies against.
      const canUseAuthorizeSign =
        messageProtocolVersion !== null &&
        messageProtocolVersion >= 1 &&
        origin !== '*' &&
        reviewModel !== null &&
        reviewModel.protocol === 'tinycloud-siwe-recap';

      if (canUseAuthorizeSign) {
        // Sol continuation contract: caller-echoed SIWE/JWK/selection are
        // NEVER trusted. First call /authorize-sign-prepare so the server
        // binds the SIWE, JWK, key, and immutable header fields into an
        // opaque single-use context. Then call /authorize-sign with the
        // token — the server narrows from its bound baseline.
        const prepareRes = await fetch(
          `${(import.meta.env.VITE_API_URL || '')}/api/delegate/authorize-sign-prepare`,
          {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              keyId: key.id,
              siwe: message,
              jwk: messageJwk,
              host: messageHost,
            }),
          },
        );
        if (!prepareRes.ok) {
          const errBody = await prepareRes.json().catch(() => ({ error: 'authorize-sign-prepare failed' }));
          throw new Error(errBody.error || `HTTP ${prepareRes.status}`);
        }
        const prepareResult = await prepareRes.json();
        const authorizationContextToken: string | undefined = prepareResult.authorizationContextToken;
        if (!authorizationContextToken) {
          throw new Error('authorize-sign-prepare did not return a context token');
        }

        // Convert the review selection to actionKey strings the server
        // recognizes. The review model IDs are NUL-separated
        // (service\0space\0path\0ability) — same format the server uses.
        const selectedActionIds: string[] = [];
        for (const grant of reviewModel!.permissions) {
          for (const action of grant.actions) {
            if (reviewSelection.has(action.id)) {
              // The action.id is already in the (service\0space\0path\0ability)
              // format because it comes from ids.actionId(service, space, path, ability).
              selectedActionIds.push(action.id);
            }
          }
        }

        const authorizeRes = await fetch(
          `${(import.meta.env.VITE_API_URL || '')}/api/delegate/authorize-sign`,
          {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              authorizationContextToken,
              selectedActionIds,
              protocolVersion: 1,
            }),
          },
        );
        if (!authorizeRes.ok) {
          const errBody = await authorizeRes.json().catch(() => ({ error: 'authorize-sign failed' }));
          throw new Error(errBody.error || `HTTP ${authorizeRes.status}`);
        }
        const authorizeResult = await authorizeRes.json();
        sendResponse({
          type: 'openkey:sign:response',
          success: true,
          signature: authorizeResult.signature,
          address: authorizeResult.address,
          // signedMessage is the ACTUAL bytes signed — never `message`.
          signedMessage: authorizeResult.signedMessage,
          selectedActionKeys: authorizeResult.selectedActionKeys,
          permissions: authorizeResult.permissions,
        });
        sendClose();
        return;
      }

      // Legacy exact-byte path: signs the caller's exact `message`. The
      // capabilities in the response are the caller's original set (no
      // narrowing happened server-side).
      const result = await api.signMessage(key.id, message);
      const effectivePermissions = reviewModel
        ? reviewModel.permissions.map((grant) => ({
            service: grant.service,
            space: grant.space,
            path: grant.path,
            actions: grant.actions
              .filter((action) => reviewSelection.has(action.id))
              .map((action) => action.ability),
          }))
        : undefined;
      sendResponse({
        type: 'openkey:sign:response',
        success: true,
        signature: result.signature,
        address: result.address,
        signedMessage: message,
        selectedActionKeys: reviewModel ? Array.from(reviewSelection) : undefined,
        permissions: effectivePermissions,
      });
      sendClose();
    } catch (e: any) {
      error = e.message || 'Signing failed';
    } finally {
      signing = false;
    }
  }

  function cancel() {
    sendResponse({
      type: 'openkey:sign:response',
      success: false,
      error: { code: 'USER_CANCELLED', message: 'User cancelled' },
    });
    sendClose();
  }

  function sendResponse(data: Record<string, unknown>) {
    // Route through the transport when this was a versioned request
    // (transport was created and we have a correlated requestId).
    if (transport && currentRequestId && messageProtocolVersion !== null) {
      const success = data.success === true || data.success === undefined
        ? true
        : Boolean(data.success);
      if (success && data.success !== false) {
        const { type: _t, success: _s, ...rest } = data as Record<string, unknown>;
        void _t; void _s;
        transport.respond({
          type: 'openkey:sign:response',
          requestId: currentRequestId,
          protocolVersion: messageProtocolVersion,
          success: true,
          data: rest,
        });
      } else {
        const err = (data.error && typeof data.error === 'object'
          ? data.error
          : { code: 'UNKNOWN', message: 'Unknown error' }) as { code: string; message: string };
        transport.respond({
          type: 'openkey:sign:response',
          requestId: currentRequestId,
          protocolVersion: messageProtocolVersion,
          success: false,
          error: err,
        });
      }
      return;
    }
    // Legacy compatibility path (wildcard origin or unversioned caller).
    if (window.opener) {
      window.opener.postMessage(data, origin);
    } else if (window.parent !== window) {
      window.parent.postMessage(data, origin);
    }
  }

  function sendClose() {
    const closeMsg = { type: 'openkey:close' };
    if (window.opener) {
      window.opener.postMessage(closeMsg, origin);
      window.close();
    } else if (window.parent !== window) {
      window.parent.postMessage(closeMsg, origin);
    }
  }

  function formatAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }

  let siweDomain = $derived(message ? parseSIWE(message)?.message.domain ?? null : null);

  let originDomain = $derived.by(() => {
    if (!origin || origin === '*') return null;
    try { return new URL(origin).hostname; } catch { return origin; }
  });

  let domainMismatch = $derived(
    siweDomain && originDomain && siweDomain !== originDomain
  );
</script>

<div class="flex-1 flex flex-col">
  <header class="flex justify-between items-center mb-6">
    <h1 class="text-xl font-semibold text-surface-50">Sign Message</h1>
    <button
      class="bg-transparent border-none text-surface-400 text-2xl cursor-pointer p-0 leading-none hover:text-surface-50 transition-colors"
      onclick={cancel}
    >
      &times;
    </button>
  </header>

  {#if !$session.data}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p class="mb-4">Sign in to sign messages</p>
      <Button href="/auth/login?redirect=/widget/sign?origin={encodeURIComponent(origin)}">Sign In</Button>
    </div>
  {:else if loading}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      Loading...
    </div>
  {:else if !key}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p>Please connect first to sign messages.</p>
    </div>
  {:else if reviewModel && reviewModel.protocol === 'tinycloud-siwe-recap'}
    <!--
      Editable TinyCloud request — render via the shared SigningApproval
      component so CLI browser, popup, and iframe show the same content.
    -->
    <SigningApproval
      model={reviewModel}
      selection={reviewSelection}
      editing={reviewEditing}
      approving={signing}
      {error}
      onApprove={signMessage}
      onCancel={cancel}
      onSelectionChange={(next) => (reviewSelection = next)}
      onEditingChange={(next) => (reviewEditing = next)}
    />
  {:else}
    <!--
      Legacy plain signMessage / non-ReCap SIWE fallback. The existing
      review UI stays for backward compatibility with pre-consolidation
      callers.
    -->
    <div class="flex flex-col gap-4 flex-1">
      <Card class="p-4">
        <span class="block text-surface-400 text-xs uppercase mb-2">Signing with:</span>
        <span class="font-semibold mr-2">{key.label || `Key ${key.keyIndex}`}</span>
        <code class="font-mono text-surface-400 text-sm">{formatAddress(key.address)}</code>
      </Card>

      {#if siweDomain}
        <Card class="p-4">
          <span class="block text-surface-400 text-xs uppercase mb-2">Request from:</span>
          <span class="text-surface-50 text-sm font-medium">{siweDomain}</span>
          {#if domainMismatch}
            <div class="mt-2 text-xs text-amber-400">
              Domain mismatch: requesting page is {originDomain} but message is from {siweDomain}
            </div>
          {/if}
        </Card>
      {/if}

      <Card class="p-4">
        <span class="block text-surface-400 text-xs uppercase mb-2">Message:</span>
        <SiweMessage {message} theme="dark" />
      </Card>

      {#if error}
        <Card class="bg-red-500/10 border-red-500 text-red-500 p-4">
          {error}
        </Card>
      {/if}

      <div class="flex gap-3 mt-auto">
        <Button variant="secondary" class="flex-1" onclick={cancel}>Cancel</Button>
        <Button class="flex-1" onclick={signMessage} disabled={signing}>
          {signing ? 'Signing...' : 'Sign Message'}
        </Button>
      </div>
    </div>
  {/if}
</div>
