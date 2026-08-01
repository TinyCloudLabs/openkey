<script lang="ts">
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { getSessionToken, isEmbedContext, setSessionToken } from '$lib/embed-passkey';
  import EmbeddedSignIn from '$lib/components/auth/embedded-sign-in.svelte';
  import { parseSIWE } from '$lib/siwe-parser';
  import Button from '$lib/components/ui/button.svelte';
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
  const inIframe = typeof window !== 'undefined' && isEmbedContext();

  let message = $state('');
  let messageProtocolVersion = $state<number | null>(null);
  let messageJwk = $state<Record<string, unknown> | null>(null);
  // Sol MAJOR-2: bind the TinyCloud host into /authorize-sign-prepare
  // so /authorize-sign cannot swap hosts.
  let messageHost = $state<string>('');
  let keyId = $state<string | null>(null);
  let key = $state<EthereumKey | null>(null);
  let loading = $state(true);
  let signing = $state(false);
  let error = $state('');
  let sessionChecked = $state(false);
  let initialized = $state(false);
  let keyFetched = $state(false);
  let contentEl = $state<HTMLDivElement | undefined>(undefined);
  let embedAuthenticated = $state(typeof window !== 'undefined' && !!getSessionToken());
  let reviewModel = $state<CapabilityReviewModel | null>(null);
  let reviewSelection = $state(new Set<string>());
  let reviewEditing = $state(false);
  let currentRequestId = $state<string | null>(null);
  let transport: WidgetTransport | null = null;
  // Sol MAJOR-9 (per-request immutable state): a second transport request
  // must NOT overwrite an in-flight one — the response would escape to
  // the wrong parent.
  let requestSealed = $state(false);
  // Sol CRITICAL-1 (distinct final approval): the iframe MUST call
  // /authorize-sign-preview so the user sees the EXACT bytes the server
  // would sign, then approves again before /authorize-sign consumes
  // the token.
  let previewSignedMessage = $state<string | null>(null);
  let previewToken = $state<string | null>(null);
  let previewing = $state(false);
  let previewApproved = $state(false);

  const isAuthenticated = $derived(inIframe ? embedAuthenticated : !!$session.data);

  const origin = $page.url.searchParams.get('origin') || '*';

  $effect(() => {
    if (typeof window !== 'undefined' && !initialized) {
      initialized = true;

      // Sol continuation contract: shared transport for real origins.
      if (origin !== '*') {
        try {
          transport = createWidgetTransport({
            origin,
            container: 'iframe',
            onRequest: handleTransportRequest,
            onClose: handleTransportClose,
            onInvalid: (reason, event) => {
              console.warn('[embed sign widget] invalid message:', reason, event.origin);
            },
          });
          transport.emitReady();
        } catch (e) {
          console.warn('[embed sign widget] transport init failed:', e);
        }
      }

      window.addEventListener('message', handleMessage);

      // Emit legacy ready only under wildcard compat path so pre-
      // consolidation SDKs still bootstrap.
      if (origin === '*') {
        const targetOrigin = new URL(window.location.href).searchParams.get('origin') || '*';
        window.parent.postMessage({ type: 'openkey:ready' }, targetOrigin);
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
    // Sol MAJOR-9: refuse overlapping requests.
    if (requestSealed) {
      console.warn(
        '[embed sign widget] refusing overlapping request; existing:',
        currentRequestId,
        'new:',
        request.requestId,
      );
      transport?.respond({
        type: 'openkey:sign:response',
        requestId: request.requestId,
        protocolVersion: request.protocolVersion,
        success: false,
        error: {
          code: 'UNKNOWN',
          message:
            'A signing request is already in progress in this widget instance. Cancel it before starting another.',
        },
      });
      return;
    }
    const data = request.data;
    currentRequestId = request.requestId;
    message = String(data.message ?? '');
    messageProtocolVersion = request.protocolVersion;
    messageJwk = (data.jwk as Record<string, unknown>) ?? null;
    messageHost = typeof data.host === 'string' ? data.host : '';
    keyId = typeof data.keyId === 'string' ? data.keyId : null;
    keyFetched = false;
    if (data.sessionToken && inIframe && typeof data.sessionToken === 'string') {
      setSessionToken(data.sessionToken);
      embedAuthenticated = true;
    }
    // Reset preview state on a fresh request.
    previewSignedMessage = null;
    previewToken = null;
    previewApproved = false;
    requestSealed = true;
  }

  function handleTransportClose() {
    // parent already closed us
  }

  // ResizeObserver to notify parent of height changes. Target the configured
  // origin — never '*'. If origin is unknown ('*'), the widget does not emit
  // resize messages (the parent will not receive them, but a wildcard target
  // would leak DOM sizing info to any listener on any origin).
  $effect(() => {
    if (!contentEl) return;
    const observer = new ResizeObserver(() => {
      if (origin === '*') return;
      const height = contentEl!.scrollHeight;
      // Route through transport (which enforces origin + validated source)
      // when available; legacy fallback for wildcard-origin compat path.
      // Sol MAJOR-9: legacy resize also carries protocolVersion=1 so the
      // SDK's strict resize check accepts it. (Legacy is only used under
      // the wildcard-origin compat path, which is refused above anyway.)
      if (transport) {
        transport.emitResize(height);
      } else {
        window.parent.postMessage({ type: 'openkey:resize', height, protocolVersion: 1 }, origin);
      }
    });
    observer.observe(contentEl);
    return () => observer.disconnect();
  });

  // Reactively update loading state when session becomes available
  $effect(() => {
    if (isAuthenticated && !sessionChecked) {
      sessionChecked = true;
      loading = false;
    }
  });

  // Reactively fetch key when session becomes available and we have a keyId
  $effect(() => {
    if (isAuthenticated && keyId && !keyFetched && !key) {
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
    // shared transport (when a real origin is present). This listener only
    // handles the wildcard-origin compat path and unversioned legacy
    // requests on real origins.
    const incomingProtocolVersion =
      typeof event.data?.protocolVersion === 'number' ? event.data.protocolVersion : null;
    const incomingRequestId =
      typeof event.data?.requestId === 'string' ? event.data.requestId : null;
    if (origin === '*') {
      if (incomingProtocolVersion !== null && incomingProtocolVersion >= 1) {
        console.warn('[embed sign widget] refusing versioned request with wildcard origin');
        return;
      }
      if (event.source !== window.parent) return;
    } else {
      if (incomingProtocolVersion !== null && incomingProtocolVersion >= 1 && incomingRequestId) {
        return; // transport handles versioned traffic
      }
      if (event.origin !== origin) return;
      if (event.source !== window.parent) return;
    }

    if (event.data?.type === 'openkey:sign:request') {
      // Sol MAJOR-9: refuse overlapping legacy request.
      if (requestSealed) {
        console.warn('[embed sign widget] refusing overlapping legacy request');
        return;
      }
      message = event.data.message;
      messageProtocolVersion = incomingProtocolVersion;
      messageJwk = event.data.jwk ?? null;
      messageHost = typeof event.data.host === 'string' ? event.data.host : '';
      keyId = event.data.keyId || null;
      keyFetched = false;
      requestSealed = true;

      // Receive session token from SDK (relayed from connect flow)
      if (event.data.sessionToken && inIframe) {
        setSessionToken(event.data.sessionToken);
        embedAuthenticated = true;
      }

      if (keyId && isAuthenticated) {
        try {
          const result = await api.getKey(keyId);
          key = result.key;
          keyFetched = true;
        } catch {
          // Key not found
        }
      }
      // reviewModel is built by a $effect below (Sol MAJOR-8) that waits
      // for `key` to be loaded before rendering a review with the real
      // signer address.
    }
  }

  // Build the capability-review model reactively. Waits for `key` so the
  // signer address is correct (Sol MAJOR-8).
  $effect(() => {
    if (!message || !key) {
      reviewModel = null;
      return;
    }
    const canEdit =
      messageProtocolVersion !== null &&
      messageProtocolVersion >= 1 &&
      origin !== '*';
    // Sol MAJOR-8: derive REAL origin/domain warning facts rather than
    // hard-coding them to false.
    let siweDomainForModel: string | null = null;
    let originHostForModel: string | null = null;
    try {
      const domainMatch = message.match(/^(.+?) wants you to sign in with your Ethereum account:$/m);
      if (domainMatch && domainMatch[1]) siweDomainForModel = domainMatch[1].trim();
    } catch { /* nothing to do; leave null */ }
    try {
      if (origin && origin !== '*') originHostForModel = new URL(origin).hostname;
    } catch { /* leave null */ }
    const domainMismatchForModel =
      !!siweDomainForModel && !!originHostForModel && siweDomainForModel !== originHostForModel;
    const originIsWildcard = origin === '*';
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
          displayName: originIsWildcard ? 'Unknown origin' : origin,
          verifiedOrigin: originIsWildcard ? null : origin,
          manifestId: null,
          manifestDigest: null,
          domainWarning: domainMismatchForModel,
          originWarning: originIsWildcard,
        },
        // Sol MAJOR-8: fail closed on requester identity — until the
        // widget resolves a signed manifest for the parent app, treat
        // every non-signer-owned space grant as cross-app-data.
        requesterAddress: null,
        requesterVerified: false,
      });
      reviewModel = model;
      reviewSelection = defaultSelection(model);
    } catch {
      reviewModel = null;
    }
  });

  function canUseAuthorizeSignFn(): boolean {
    return (
      messageProtocolVersion !== null &&
      messageProtocolVersion >= 1 &&
      origin !== '*' &&
      reviewModel !== null &&
      reviewModel.protocol === 'tinycloud-siwe-recap'
    );
  }

  function currentSelectedActionIds(): string[] {
    if (!reviewModel) return [];
    const out: string[] = [];
    for (const grant of reviewModel.permissions) {
      for (const action of grant.actions) {
        if (reviewSelection.has(action.id)) {
          out.push(action.id);
        }
      }
    }
    return out;
  }

  // Sol CRITICAL-1: preview step for iframe.
  async function requestPreview(): Promise<void> {
    if (!key || !message) return;
    if (!canUseAuthorizeSignFn()) return;
    previewing = true;
    error = '';
    previewApproved = false;
    try {
      let token = previewToken;
      if (!token) {
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
        token = typeof prepareResult.authorizationContextToken === 'string'
          ? prepareResult.authorizationContextToken
          : null;
        if (!token) throw new Error('authorize-sign-prepare did not return a context token');
        previewToken = token;
      }
      const previewRes = await fetch(
        `${(import.meta.env.VITE_API_URL || '')}/api/delegate/authorize-sign-preview`,
        {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            authorizationContextToken: token,
            selectedActionIds: currentSelectedActionIds(),
          }),
        },
      );
      if (!previewRes.ok) {
        const errBody = await previewRes.json().catch(() => ({ error: 'authorize-sign-preview failed' }));
        throw new Error(errBody.error || `HTTP ${previewRes.status}`);
      }
      const previewResult = await previewRes.json();
      if (typeof previewResult.signedMessage !== 'string' || !previewResult.signedMessage) {
        throw new Error('authorize-sign-preview did not return signedMessage');
      }
      previewSignedMessage = previewResult.signedMessage;
    } catch (e: any) {
      error = e.message || 'Preview failed';
      previewToken = null;
      previewSignedMessage = null;
    } finally {
      previewing = false;
    }
  }

  async function approveAndSign() {
    if (!key || !message) return;
    signing = true;
    error = '';
    try {
      if (canUseAuthorizeSignFn()) {
        if (!previewToken || !previewSignedMessage) {
          throw new Error('Preview required before approval — call requestPreview() first');
        }
        const selectedActionIds = currentSelectedActionIds();
        const authorizeRes = await fetch(
          `${(import.meta.env.VITE_API_URL || '')}/api/delegate/authorize-sign`,
          {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              authorizationContextToken: previewToken,
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
        if (authorizeResult.signedMessage !== previewSignedMessage) {
          throw new Error('Server signed bytes differ from the previewed bytes — refusing to accept');
        }
        sendResponse({
          type: 'openkey:sign:response',
          success: true,
          signature: authorizeResult.signature,
          address: authorizeResult.address,
          signedMessage: authorizeResult.signedMessage,
          selectedActionKeys: authorizeResult.selectedActionKeys,
          permissions: authorizeResult.permissions,
        });
        sendClose();
        return;
      }

      // Legacy exact-byte path (no narrowing).
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

  function invalidatePreviewForSelectionEdit() {
    previewSignedMessage = null;
    previewApproved = false;
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
    // Route through transport when this was a versioned request.
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
    window.parent.postMessage(data, origin);
  }

  function sendClose() {
    window.parent.postMessage({ type: 'openkey:close' }, origin);
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

<div bind:this={contentEl} class="flex flex-col gap-4 bg-[#fafafa] p-4 rounded-2xl">
  <!-- Header -->
  <div class="flex flex-col items-center gap-3">
    <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-surface-800 to-surface-900 flex items-center justify-center shadow-sm">
      <svg class="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
      </svg>
    </div>
    <h1 class="text-lg font-semibold text-surface-900">Sign Message</h1>
  </div>

  <!-- Card body -->
  <div class="bg-white border border-surface-200 rounded-2xl shadow-sm p-5">
    {#if !isAuthenticated}
      <EmbeddedSignIn
        prompt="Sign in to review and sign this message"
        onauthenticated={() => { embedAuthenticated = true; }}
      />
    {:else if loading}
      <div class="flex flex-col items-center justify-center text-center text-surface-400 py-6">
        <svg class="w-6 h-6 animate-spin text-surface-400 mb-3" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
        </svg>
        <span class="text-sm text-surface-500">Loading...</span>
      </div>
    {:else if !key}
      <div class="flex flex-col items-center justify-center text-center text-surface-500 py-4">
        <p class="text-sm">Please connect first to sign messages.</p>
      </div>
    {:else if reviewModel && reviewModel.protocol === 'tinycloud-siwe-recap' && previewSignedMessage && canUseAuthorizeSignFn()}
      <!--
        Sol CRITICAL-1: distinct final-approval screen for iframe. The
        user has previewed the EXACT bytes the server will sign; they
        must approve those specific bytes before /authorize-sign is
        invoked.
      -->
      <div class="flex flex-col gap-3">
        <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
          <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Final review — server-authoritative bytes</span>
          <p class="text-surface-500 text-xs mb-2">
            These are the EXACT bytes the server will sign for the current selection.
          </p>
          <pre class="whitespace-pre-wrap break-all text-xs text-surface-700 font-mono max-h-72 overflow-y-auto">{previewSignedMessage}</pre>
        </div>
        {#if error}
          <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl text-sm" role="alert">{error}</div>
        {/if}
        <div class="flex gap-2 mt-1">
          <Button variant="secondary" size="sm" class="flex-1 rounded-xl" onclick={() => { previewSignedMessage = null; }}>Back</Button>
          <Button size="sm" class="flex-1 rounded-xl" onclick={approveAndSign} disabled={signing}>
            {signing ? 'Signing...' : 'Approve exact bytes'}
          </Button>
        </div>
      </div>
    {:else if reviewModel && reviewModel.protocol === 'tinycloud-siwe-recap'}
      <!--
        Editable TinyCloud request — render via the shared SigningApproval
        component. The onApprove handler routes through requestPreview()
        so the user must review the server-returned candidate bytes before
        the final /authorize-sign step.
      -->
      <SigningApproval
        model={reviewModel}
        selection={reviewSelection}
        editing={reviewEditing}
        approving={signing || previewing}
        {error}
        onApprove={() => {
          if (canUseAuthorizeSignFn()) {
            requestPreview();
          } else {
            approveAndSign();
          }
        }}
        onCancel={cancel}
        onSelectionChange={(next) => {
          reviewSelection = next;
          invalidatePreviewForSelectionEdit();
        }}
        onEditingChange={(next) => (reviewEditing = next)}
      />
    {:else}
      <div class="flex flex-col gap-3">
        <!-- Signing with -->
        <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
          <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Signing with</span>
          <div class="flex items-center gap-2">
            <span class="font-medium text-sm text-surface-900">{key.label || `Key ${key.keyIndex}`}</span>
            <code class="font-mono text-surface-400 text-xs">{formatAddress(key.address)}</code>
          </div>
        </div>

        <!-- Request from -->
        {#if siweDomain}
          <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
            <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Request from</span>
            <span class="text-sm font-medium text-surface-900">{siweDomain}</span>
            {#if domainMismatch}
              <div class="mt-1.5 text-xs text-amber-600">
                Domain mismatch: requesting page is {originDomain} but message is from {siweDomain}
              </div>
            {/if}
          </div>
        {/if}

        <!-- Message -->
        <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
          <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Message</span>
          <SiweMessage {message} theme="light" />
        </div>

        {#if error}
          <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex gap-2 mt-1">
          <Button variant="secondary" size="sm" class="flex-1 rounded-xl" onclick={cancel}>Cancel</Button>
          <Button size="sm" class="flex-1 rounded-xl" onclick={approveAndSign} disabled={signing}>
            {signing ? 'Signing...' : 'Sign Message'}
          </Button>
        </div>
      </div>
    {/if}
  </div>

  <!-- Trust badge -->
  <div class="flex items-center justify-center gap-1.5 text-surface-400">
    <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
    <span class="text-xs">Protected by TEE hardware security</span>
  </div>
</div>
