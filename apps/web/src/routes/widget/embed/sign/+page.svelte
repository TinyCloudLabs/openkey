<script lang="ts">
  import { page } from '$app/stores';
  import { tick } from 'svelte';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { getSessionToken, isEmbedContext, withSessionCredential } from '$lib/embed-passkey';
  import EmbeddedSignIn from '$lib/components/auth/embedded-sign-in.svelte';
  import { passkeysSupportedFromParams } from '$lib/passkey-support';
  import Button from '$lib/components/ui/button.svelte';
  import IframeSigningAdapter from '$lib/components/signing/iframe-signing-adapter.svelte';
  import { originAuthority, requesterDisplayName } from '$lib/requester-display';
  import { requestedActionIds, selectionFromPreview } from '$lib/widget-selection';
  import { expiryAt, siweExpiration } from '$lib/approval-expiry';
  import {
    parseCapabilityReview,
    parseSiweChainId,
    defaultSelection,
    annotateAppScopedGrants,
    type CapabilityReviewModel,
    type DeclaredAppScope,
    checkSiweOrigin,
  } from '@openkey/capability-review';
  import SiweOriginRefusal from '$lib/components/signing/siwe-origin-refusal.svelte';
  import ServerReplyRefusal from '$lib/components/signing/server-reply-refusal.svelte';
  import { hasSignResult, hasText, readReply, ServerReplyError, SERVER_REPLY_ERROR } from '$lib/server-reply';
  import {
    createIframeLayoutGate,
    type IframeLayoutGate,
    createWidgetTransport,
    type WidgetRequest,
    type WidgetTransport,
  } from '$lib/widget-transport';

  const session = authClient.useSession();
  const inIframe = typeof window !== 'undefined' && isEmbedContext();

  let message = $state('');
  let messageProtocolVersion = $state<number | null>(null);
  let authorizationProtocolVersion = $state<number | null>(null);
  let messageJwk = $state<Record<string, unknown> | null>(null);
  // Sol MAJOR-2: bind the TinyCloud host into /authorize-sign-prepare
  // so /authorize-sign cannot swap hosts.
  let messageHost = $state<string>('');
  let keyId = $state<string | null>(null);
  let key = $state<EthereumKey | null>(null);
  let loading = $state(true);
  let signing = $state(false);
  let error = $state('');
  // The HTTP status of a reply that could not be read; shown in Advanced details only.
  let replyFailureStatus = $state<number | null>(null);
  let sessionChecked = $state(false);
  let initialized = $state(false);
  let keyFetched = $state(false);
  let keyError = $state('');
  let contentEl = $state<HTMLDivElement | undefined>(undefined);
  let embedAuthenticated = $state(typeof window !== 'undefined' && !!getSessionToken());
  let reviewModel = $state<CapabilityReviewModel | null>(null);
  let reviewSourceMessage = $state<string | null>(null);
  let reviewSelection = $state(new Set<string>());
  let reviewEditing = $state(false);
  let currentRequestId = $state<string | null>(null);
  let transport: WidgetTransport | null = null;
  let layoutReady = $state(false);
  let layoutError = $state('');
  let layoutGate: IframeLayoutGate | null = null;
  let pendingLayoutAck: { height: number; layoutId: number } | null = null;
  let keyReadGeneration = 0;
  let keyOwnerToken: string | null = null;
  let keyOwnerSessionId: string | undefined;
  let keyReadToken: string | null = null;
  let keyReadSessionId: string | null | undefined;
  // Presentation envelope forwarded by the SDK. Display-only. Trust is
  // set only from the server prepare response (see below).
  let requestPresentation = $state<Record<string, unknown> | null>(null);
  let serverMetadataTrust = $state<
    { status: 'verified' | 'origin-bound' | 'unsigned'; reason: string } | null
  >(null);
  let serverVerifiedManifest = $state<
    | {
        name?: string;
        appId?: string;
        manifestId?: string;
        manifestDigest?: string;
        reportedOrigin?: string;
        // Sol MAJOR-2: origin-bound app-scope declarations. Display-only
        // enrichment for KV/secret grants; never widens authority. The
        // widget forwards these to `annotateAppScopedGrants` — a match
        // becomes a compact metadata label, never a severity change.
        declaredAppScope?: DeclaredAppScope;
      }
    | null
  >(null);
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
  let previewApprovalToken = $state<string | null>(null);
  let previewing = $state(false);
  // TC-2272: how long from approval the user chose; null keeps the app's own expiry.
  let expiryChoiceMs = $state<number | null>(null);
  let previewApproved = $state(false);
  // Sol MAJOR-3 (continuation): external-key review mode. See widget/sign.
  let externalSignMode = $state(false);
  let expiryChangeable = $state(false);

  const isAuthenticated = $derived(inIframe ? embedAuthenticated : !!$session.data);

  const origin = $page.url.searchParams.get('origin') || '*';
  const v2 = $page.url.searchParams.get('protocolVersion') === '2';
  const phaseRequestId = v2 ? $page.url.searchParams.get('requestId') : null;
  const phaseKeyId = v2 ? $page.url.searchParams.get('keyId') : null;
  const passkeysSupported = passkeysSupportedFromParams($page.url.searchParams);

  function applyPendingLayout() {
    const ack = pendingLayoutAck;
    if (!ack) return;
    if (!layoutGate?.isCurrent(ack.layoutId)) {
      pendingLayoutAck = null;
      return;
    }
    if (window.innerHeight + 1 < ack.height) return;
    pendingLayoutAck = null;
    layoutGate.applied(ack.height, ack.layoutId);
  }

  $effect(() => {
    if (typeof window !== 'undefined' && !initialized) {
      initialized = true;

      // V2 phases must be pinned to their URL identity before ready is sent.
      if (origin !== '*' && (!v2 || (phaseRequestId && phaseKeyId))) {
        try {
          if (v2) {
            layoutGate = createIframeLayoutGate(
              (height, layoutId) => transport?.emitResize(height, layoutId),
              (ready, layoutId) => {
                transport?.emitLayoutSignal(ready, layoutId);
                layoutReady = ready;
              },
              () => {
                pendingLayoutAck = null;
                layoutError = 'Review layout could not be confirmed. Cancel and try again.';
              },
            );
          }
          transport = createWidgetTransport({
            origin,
            container: 'iframe',
            protocolVersion: v2 ? 2 : 1,
            requestId: phaseRequestId ?? undefined,
            onRequest: handleTransportRequest,
            onClose: handleTransportClose,
            onLayoutApplied: (height, layoutId) => {
              // A valid ACK may arrive before the iframe observes its new viewport.
              // Apply only the current revision once that viewport catches up.
              if (!layoutGate?.isCurrent(layoutId)) return;
              pendingLayoutAck = { height, layoutId };
              applyPendingLayout();
            },
            onInvalid: (reason, event) => {
              console.warn('[embed sign widget] invalid message:', reason, event.origin);
            },
          });
          if (v2) {
            window.addEventListener('resize', applyPendingLayout);
            window.visualViewport?.addEventListener('resize', applyPendingLayout);
          }
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
      window.removeEventListener('message', handleMessage);
      window.removeEventListener('resize', applyPendingLayout);
      window.visualViewport?.removeEventListener('resize', applyPendingLayout);
      layoutGate?.destroy();
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
    if (v2 && request.data.keyId !== phaseKeyId) {
      transport?.respond({
        type: 'openkey:sign:response',
        requestId: request.requestId,
        protocolVersion: 2,
        success: false,
        error: { code: 'UNKNOWN', message: 'Selected key does not match this signing phase.' },
      });
      return;
    }
    const sameRead = v2 && keyFetched && request.data.keyId === phaseKeyId &&
      keyReadToken === getSessionToken() &&
      keyReadSessionId === (inIframe ? null : $session.data?.session?.id);
    // An early key result may have been measured before transport bound its
    // request ID. Reissue the layout after binding this request.
    pendingLayoutAck = null;
    layoutGate?.changed();
    if (!sameRead) {
      keyReadGeneration++;
      key = null;
      keyOwnerToken = null;
      keyOwnerSessionId = undefined;
      keyError = '';
      keyFetched = false;
    }
    const data = request.data;
    currentRequestId = request.requestId;
    message = String(data.message ?? '');
    messageProtocolVersion = request.protocolVersion;
    authorizationProtocolVersion = v2
      ? (data.authorizationProtocolVersion === 1 ? 1 : null)
      : request.protocolVersion;
    messageJwk = (data.jwk as Record<string, unknown>) ?? null;
    messageHost = typeof data.host === 'string' ? data.host : '';
    keyId = typeof data.keyId === 'string' ? data.keyId : null;
    // Sol MAJOR-3 (continuation): capture the externalSign flag.
    externalSignMode = data.externalSign === true;
    // TC-2272: only an SDK that accepts a different signed expiry sends this; without it the
    // approval shows no expiry control and the app's own expiry is signed.
    expiryChangeable = data.expiryChangeable === true;
    // Envelope (display-only). Widget transport already validated + size-
    // bounded the object. Trust decision is deferred to /authorize-sign-
    // prepare and populated into serverMetadataTrust below.
    requestPresentation =
      data.presentation && typeof data.presentation === 'object'
        ? (data.presentation as Record<string, unknown>)
        : null;
    serverMetadataTrust = null;
    serverVerifiedManifest = null;
    reviewModel = null;
    reviewSourceMessage = null;
    reviewSelection = new Set();
    // The URL-selected key read is reused when the verified session is unchanged.
    // A sessionToken in the request is ignored: the session comes only from
    // OpenKey-origin storage or cookies (TC-688).
    // Reset preview state on a fresh request.
    previewSignedMessage = null;
    previewToken = null;
    previewApprovalToken = null;
    previewApproved = false;
    requestSealed = true;
  }

  function handleTransportClose() {
    // parent already closed us
  }

  // Measure natural content height, including review text below the initial
  // iframe viewport. The host may constrain its own viewport and scroll it.
  // A mutation immediately revokes approval even if text changes without
  // changing height; layoutId prevents late same-height acks from reopening it.
  $effect(() => {
    if (!contentEl) return;
    const content = contentEl;
    let frame = 0;
    let fallback: ReturnType<typeof setTimeout> | undefined;
    const measure = () => {
      if (origin === '*') return;
      const height = Math.max(content.scrollHeight, Math.ceil(content.getBoundingClientRect().height));
      if (v2) {
        const review = content.querySelector('[role="dialog"]');
        layoutGate?.measure(
          height,
          (!!review && review.getClientRects().length > 0 && getComputedStyle(review).visibility === 'visible') ||
          ((!isAuthenticated || !!keyError) && content.getClientRects().length > 0),
        );
        return;
      }
      if (currentRequestId && messageProtocolVersion !== null) {
        if (transport) {
          transport.emitResize(height);
        } else {
          window.parent.postMessage(
            { type: 'openkey:resize', height, protocolVersion: messageProtocolVersion, requestId: currentRequestId },
            origin,
          );
        }
        return;
      }
      window.parent.postMessage({ type: 'openkey:resize', height }, origin);
    };
    const observer = new ResizeObserver(measure);
    observer.observe(content);
    if (v2) {
      const mutation = new MutationObserver(() => {
        pendingLayoutAck = null;
        layoutGate?.changed();
        cancelAnimationFrame(frame);
        clearTimeout(fallback);
        // Hidden iframes can suspend rAF (and ResizeObserver delivery).
        // A timer still measures the rendered review and starts the ACK gate.
        frame = requestAnimationFrame(() => {
          clearTimeout(fallback);
          fallback = undefined;
          measure();
        });
        fallback = setTimeout(() => {
          cancelAnimationFrame(frame);
          frame = 0;
          fallback = undefined;
          measure();
        }, 150);
      });
      mutation.observe(content, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ['open', 'class', 'style'] });
      return () => {
        observer.disconnect();
        mutation.disconnect();
        cancelAnimationFrame(frame);
        clearTimeout(fallback);
      };
    }
    return () => observer.disconnect();
  });

  $effect(() => {
    if (isAuthenticated && !sessionChecked) {
      sessionChecked = true;
      loading = false;
    }
  });
  // Authentication and a prefetched key error can render before transport
  // binds its request ID. Measure the current step after that binding so
  // the hidden host frame always exposes Sign In or Cancel.
  $effect(() => {
    if (!v2 || !requestSealed || (isAuthenticated && !keyError)) return;
    void tick().then(() => {
      if ((isAuthenticated && !keyError) || !contentEl) return;
      layoutGate?.measure(
        Math.max(contentEl.scrollHeight, Math.ceil(contentEl.getBoundingClientRect().height)),
        true,
      );
    });
  });

  $effect(() => {
    const selectedId = keyId ?? phaseKeyId;
    if (!isAuthenticated || !selectedId || (!v2 && !requestSealed) || keyFetched) return;
    keyFetched = true;
    const requestId = currentRequestId ?? phaseRequestId;
    const token = getSessionToken();
    const sessionId = inIframe ? null : $session.data?.session?.id;
    keyReadToken = token;
    keyReadSessionId = sessionId;
    const generation = ++keyReadGeneration;
    api.getKey(selectedId).then(({ key: found }) => {
      if (generation !== keyReadGeneration || (keyId ?? phaseKeyId) !== selectedId ||
          (currentRequestId ?? phaseRequestId) !== requestId) return;
      if (
        getSessionToken() !== token ||
        (inIframe ? null : $session.data?.session?.id) !== sessionId ||
        found.id !== selectedId
      ) {
        keyError = 'Selected key could not be loaded for this session.';
        return;
      }
      // Detail endpoint is owner-scoped and selects only public columns.
      key = {
        id: found.id, address: found.address, publicKey: found.publicKey,
        keyIndex: found.keyIndex, label: found.label, keyType: found.keyType,
        createdAt: found.createdAt, archivedAt: found.archivedAt, isPrimary: found.isPrimary,
      };
      keyOwnerToken = token;
      keyOwnerSessionId = sessionId ?? undefined;
    }).catch(() => {
      if (generation === keyReadGeneration && getSessionToken() === token) keyError = 'Selected key could not be loaded.';
    });
  });

  function handleMessage(event: MessageEvent) {
    if (v2) return;
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
      keyReadGeneration++;
      key = null;
      keyOwnerToken = null;
      keyOwnerSessionId = undefined;
      keyError = '';
      message = event.data.message;
      messageProtocolVersion = incomingProtocolVersion;
      authorizationProtocolVersion = incomingProtocolVersion;
      messageJwk = event.data.jwk ?? null;
      messageHost = typeof event.data.host === 'string' ? event.data.host : '';
      keyId = event.data.keyId || null;
      requestPresentation =
        event.data.presentation && typeof event.data.presentation === 'object'
          ? event.data.presentation
          : null;
      serverMetadataTrust = null;
      serverVerifiedManifest = null;
      keyFetched = false;
      requestSealed = true;

      // The single reactive key loader handles legacy and versioned
      // requests once the current authenticated session is available.
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
    const canEdit = authorizationProtocolVersion === 1 && origin !== '*';
    // Sol MAJOR-8: derive REAL origin/domain warning facts rather than
    // hard-coding them to false.
    let siweDomainForModel: string | null = null;
    let originHostForModel: string | null = null;
    try {
      const domainMatch = message.match(/^(.+?) wants you to sign in with your Ethereum account:$/m);
      if (domainMatch && domainMatch[1]) siweDomainForModel = domainMatch[1].trim();
    } catch { /* nothing to do; leave null */ }
    originHostForModel = originAuthority(origin);
    const domainMismatchForModel =
      !!siweDomainForModel && !!originHostForModel && siweDomainForModel !== originHostForModel;
    const originIsWildcard = origin === '*';
    // Envelope + server-decided trust wiring. Same rules as the popup
    // widget: envelope is display-only, trust is authoritative from the
    // server prepare response.
    const envelope = requestPresentation;
    const envelopeDisplayName =
      envelope && typeof envelope.displayName === 'string' && envelope.displayName
        ? envelope.displayName
        : null;
    const envelopeReasonText =
      envelope && typeof envelope.reason === 'string' && envelope.reason ? envelope.reason : '';
    const envelopeManifestId =
      envelope && typeof envelope.manifestId === 'string' && envelope.manifestId
        ? envelope.manifestId
        : null;
    const envelopeManifestDigest =
      envelope && typeof envelope.manifestDigest === 'string' && envelope.manifestDigest
        ? envelope.manifestDigest
        : null;
    const effectiveTrust = serverMetadataTrust ?? {
      status: 'unsigned' as const,
      reason: envelope
        ? 'awaiting server verification of manifest envelope'
        : 'no manifest supplied',
    };
    // Sol MAJOR-4: compute manifest name/ID provenance alongside their
    // display strings so the Advanced-details disclosure can render
    // caller-supplied fields with a visible "unverified" hint. Server
    // fields count as verified/origin-bound only when trust actually
    // reached that status; anything else falls back to the caller
    // envelope AND is labelled `caller`.
    const trustStatus = effectiveTrust.status;
    const manifestNameFromServer =
      trustStatus === 'verified' || trustStatus === 'origin-bound'
        ? serverVerifiedManifest?.name ?? null
        : null;
    const manifestName =
      manifestNameFromServer ?? envelopeDisplayName ?? null;
    const manifestNameProvenance: 'verified' | 'origin-bound' | 'caller' | 'none' =
      manifestNameFromServer && trustStatus === 'verified'
        ? 'verified'
        : manifestNameFromServer && trustStatus === 'origin-bound'
          ? 'origin-bound'
          : envelopeDisplayName
            ? 'caller'
            : 'none';
    const manifestIdFromServer =
      trustStatus === 'verified' || trustStatus === 'origin-bound'
        ? serverVerifiedManifest?.manifestId ?? null
        : null;
    const displayManifestId =
      manifestIdFromServer ?? envelopeManifestId ?? null;
    const manifestIdProvenance: 'verified' | 'origin-bound' | 'caller' | 'none' =
      manifestIdFromServer && trustStatus === 'verified'
        ? 'verified'
        : manifestIdFromServer && trustStatus === 'origin-bound'
          ? 'origin-bound'
          : envelopeManifestId
            ? 'caller'
            : 'none';
    const displayManifestDigest =
      serverVerifiedManifest?.manifestDigest ?? envelopeManifestDigest;
    const displayName = requesterDisplayName(manifestNameFromServer, origin);
    // Sol Blocker A (this iteration): derive the signer chain ID from the
    // actual SIWE bytes that will be signed, not from a hard-coded default.
    // The app-scoped-secret proof (expectedSignerSecretsSpace /
    // isSignerOwnedSecretsSpace) pins the signer's canonical secrets space
    // to `tinycloud:pkh:eip155:<chainId>:<address>:secrets`. A mismatched
    // chain ID would silently pass the ownership check for a different-
    // chain resource URI and let a wrong-chain grant escape to standard
    // severity. When the SIWE has no parseable `Chain ID:` line (legacy
    // messages, malformed input) we fall back to `0` so the ownership
    // check fails closed rather than pretending the request was on mainnet.
    const parsedChainId = parseSiweChainId(message);
    const signerChainId = parsedChainId ?? 0;
    try {
      const model = parseCapabilityReview({
        message,
        signer: {
          label: 'Selected key',
          address: key.address,
          chainId: signerChainId,
          provenance: key.keyType === 'EXTERNAL' ? 'external' : 'managed',
        },
        editable: canEdit,
        metadataTrust: effectiveTrust,
        reason: envelopeReasonText
          ? { text: envelopeReasonText, source: 'caller' }
          : { text: '', source: 'none' },
        requester: {
          displayName,
          verifiedOrigin: originIsWildcard ? null : origin,
          // Sol minor: pass origin-bound appId when the server verified
          // it. Never fall back to caller-echoed envelope data.
          appId: serverVerifiedManifest?.appId ?? null,
          // Sol MAJOR-4: manifest name + ID with honest provenance so
          // the shared component can render each caller-echoed field
          // with a visible "unverified" hint. Never mark a fall-back
          // envelope value as origin-bound.
          manifestName,
          manifestNameProvenance,
          manifestId: displayManifestId,
          manifestIdProvenance,
          manifestDigest: displayManifestDigest,
          domainWarning: domainMismatchForModel,
          originWarning: originIsWildcard,
        },
      });
      // Sol MAJOR-2: app-scoped-secret trust rule. When the SERVER
      // origin-bound the manifest (`origin-bound` or `verified` trust
      // status) AND that manifest declared a scoped secret matching the
      // grant's exact (secretName, scope, actions) triple, add a
      // compact "app-scoped" metadata label. In every other case the
      // grant is left untouched — including its severity, which
      // metadata may NEVER lower. See app-scope.ts for the rule.
      const nextReviewModel = annotateAppScopedGrants(
        model,
        serverVerifiedManifest?.declaredAppScope,
      );
      reviewModel = previewSignedMessage
        ? { ...nextReviewModel, rawMessage: previewSignedMessage, expiry: siweExpiration(previewSignedMessage) ?? nextReviewModel.expiry }
        : nextReviewModel;
      if (reviewSourceMessage !== message) {
        reviewSelection = defaultSelection(reviewModel);
        reviewSourceMessage = message;
      }
    } catch {
      reviewModel = null;
    }
  });

  function canUseAuthorizeSignFn(): boolean {
    return (
      authorizationProtocolVersion === 1 &&
      origin !== '*' &&
      reviewModel !== null &&
      reviewModel.protocol === 'tinycloud-siwe-recap'
    );
  }

  function currentSelectedActionIds(): string[] {
    return requestedActionIds(reviewModel, reviewSelection);
  }

  function currentKeyBelongsToSession(): boolean {
    if (
      isAuthenticated &&
      key?.id === keyId &&
      getSessionToken() === keyOwnerToken &&
      (inIframe || $session.data?.session?.id === keyOwnerSessionId)
    ) return true;
    keyReadGeneration++;
    key = null;
    keyError = 'Signing session changed. Cancel and try again.';
    layoutGate?.changed();
    error = 'Signing session changed. Cancel and try again.';
    return false;
  }

  // Sol CRITICAL-1: preview step for iframe.
  async function requestPreview(): Promise<void> {
    if (!key || !message) return;
    if (siweRefusal) return;
    if (!canUseAuthorizeSignFn()) return;
    if (v2 && !layoutGate?.canApprove()) return;
    if (!currentKeyBelongsToSession()) return;
    previewing = true;
    error = '';
    previewApproved = false;
    try {
      let token = previewToken;
      if (!token) {
        const reportedOriginForPrepare =
          origin && origin !== '*' && origin.startsWith('https://') ? origin : undefined;
        const prepareRes = await fetch(
          `${(import.meta.env.VITE_API_URL || '')}/api/delegate/authorize-sign-prepare`,
          withSessionCredential({
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              keyId: key.id,
              siwe: message,
              jwk: messageJwk,
              host: messageHost,
              presentation: requestPresentation ?? undefined,
              reportedOrigin: reportedOriginForPrepare,
              requestOrigin: origin === '*' ? undefined : origin,
              // Bound into the authorization context: the server refuses a changed expiry unless the app opted in.
              ...(expiryChangeable ? { expiryChangeable: true } : {}),
            }),
          }),
        );
        const prepareResult = await readReply(
          prepareRes,
          (body) => hasText(body, 'authorizationContextToken'),
          'authorize-sign-prepare failed',
        );
        token = typeof prepareResult.authorizationContextToken === 'string'
          ? prepareResult.authorizationContextToken
          : null;
        if (!token) throw new Error('authorize-sign-prepare did not return a context token');
        previewToken = token;
        // Adopt server trust decision + verified manifest fields.
        if (
          prepareResult.metadataTrust &&
          typeof prepareResult.metadataTrust === 'object' &&
          typeof prepareResult.metadataTrust.status === 'string' &&
          typeof prepareResult.metadataTrust.reason === 'string'
        ) {
          const status = prepareResult.metadataTrust.status;
          if (status === 'verified' || status === 'origin-bound' || status === 'unsigned') {
            serverMetadataTrust = { status, reason: prepareResult.metadataTrust.reason };
          }
        }
        if (
          prepareResult.verifiedManifest &&
          typeof prepareResult.verifiedManifest === 'object'
        ) {
          const vm = prepareResult.verifiedManifest as Record<string, unknown>;
          // Sol MAJOR-2: adopt the origin-bound app-scope declarations
          // the server extracted from the ALREADY-digest-matched
          // well-known manifest. Forwarded as display-only enrichment
          // into `annotateAppScopedGrants`; never widens authority.
          let declaredAppScope: DeclaredAppScope | undefined;
          if (
            vm.declaredAppScope &&
            typeof vm.declaredAppScope === 'object' &&
            !Array.isArray(vm.declaredAppScope)
          ) {
            const das = vm.declaredAppScope as Record<string, unknown>;
            const secretsRaw = Array.isArray(das.secrets) ? das.secrets : [];
            const permsRaw = Array.isArray(das.permissions) ? das.permissions : [];
            const secrets = secretsRaw
              .filter(
                (s): s is { secretName: string; scope?: string; actions: string[] } =>
                  !!s &&
                  typeof s === 'object' &&
                  typeof (s as any).secretName === 'string' &&
                  Array.isArray((s as any).actions) &&
                  (s as any).actions.every((a: unknown) => typeof a === 'string'),
              )
              .map((s) => ({
                secretName: s.secretName,
                scope: typeof (s as any).scope === 'string' ? (s as any).scope : undefined,
                actions: s.actions,
              }));
            const permissions = permsRaw
              .filter(
                (p): p is { service: string; space?: string; path: string; actions: string[] } =>
                  !!p &&
                  typeof p === 'object' &&
                  typeof (p as any).service === 'string' &&
                  typeof (p as any).path === 'string' &&
                  Array.isArray((p as any).actions) &&
                  (p as any).actions.every((a: unknown) => typeof a === 'string'),
              )
              .map((p) => ({
                service: p.service,
                space: typeof (p as any).space === 'string' ? (p as any).space : undefined,
                path: p.path,
                actions: p.actions,
              }));
            declaredAppScope = {
              prefix: typeof das.prefix === 'string' ? das.prefix : undefined,
              defaultSpace:
                typeof das.defaultSpace === 'string' ? das.defaultSpace : undefined,
              secrets: secrets.length > 0 ? secrets : undefined,
              permissions: permissions.length > 0 ? permissions : undefined,
            };
          }
          serverVerifiedManifest = {
            name: typeof vm.name === 'string' ? vm.name : undefined,
            appId: typeof vm.appId === 'string' ? vm.appId : undefined,
            manifestId: typeof vm.manifestId === 'string' ? vm.manifestId : undefined,
            manifestDigest:
              typeof vm.manifestDigest === 'string' ? vm.manifestDigest : undefined,
            reportedOrigin:
              typeof vm.reportedOrigin === 'string' ? vm.reportedOrigin : undefined,
            declaredAppScope,
          };
        }
      }
      const selectedIds = currentSelectedActionIds();
      const previewRes = await fetch(
        `${(import.meta.env.VITE_API_URL || '')}/api/delegate/authorize-sign-preview`,
        withSessionCredential({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            authorizationContextToken: token,
            selectedActionIds: selectedIds,
            // TC-2272: only when the user changed it; the app's own expiry stays the default.
            ...(expiryChoiceMs === null ? {} : { expirationTime: expiryAt(expiryChoiceMs) }),
          }),
        }),
      );
      const previewResult = await readReply(
        previewRes,
        (body) => hasText(body, 'signedMessage', 'previewApprovalToken'),
        'authorize-sign-preview failed',
      );
      if (typeof previewResult.signedMessage !== 'string' || !previewResult.signedMessage) {
        throw new Error('authorize-sign-preview did not return signedMessage');
      }
      // Sol CRITICAL-1: capture the preview-approval token that seals
      // the exact (selection, signedMessage) pair. /authorize-sign
      // requires this token to proceed.
      if (typeof previewResult.previewApprovalToken !== 'string' || !previewResult.previewApprovalToken) {
        throw new Error('authorize-sign-preview did not return a previewApprovalToken — server is out of date');
      }
      reviewSelection = selectionFromPreview(previewResult, selectedIds);
      previewSignedMessage = previewResult.signedMessage;
      previewApprovalToken = previewResult.previewApprovalToken;
    } catch (e: any) {
      if (e instanceof ServerReplyError) unreadableReply(e.status);
      else error = e.message || 'Preview failed';
      previewToken = null;
      previewSignedMessage = null;
      previewApprovalToken = null;
    } finally {
      previewing = false;
    }
  }

  async function approveAndSign() {
    if (!key || !message) return;
    if (siweRefusal) {
      error = siweRefusal.message;
      return;
    }
    if (v2 && !layoutGate?.canApprove()) return;
    if (!currentKeyBelongsToSession()) return;
    // Fail-closed: refuse to sign a malformed ReCap regardless of path.
    // Silently signing exact bytes for a decoded-to-nothing ReCap would
    // drop the caller's capability payload without their consent.
    if (reviewModel && reviewModel.protocol === 'malformed-recap') {
      error =
        'Refusing to sign: this SIWE carries a capability payload that could not be decoded.';
      return;
    }
    signing = true;
    error = '';
    try {
      if (canUseAuthorizeSignFn()) {
        if (!previewToken || !previewSignedMessage || !previewApprovalToken) {
          throw new Error('Preview required before approval — call requestPreview() first');
        }
        const selectedActionIds = currentSelectedActionIds();
        // Sol MAJOR-3 (continuation): external-key mode. Hand the preview
        // payload back to the SDK; the SDK invokes the user's wallet and
        // completes /authorize-sign with the resulting signature.
        if (externalSignMode) {
          sendResponse({
            type: 'openkey:externalSign:approve',
            success: true,
            authorizationContextToken: previewToken,
            previewApprovalToken,
            signedMessage: previewSignedMessage,
            selectedActionIds,
            address: key.address,
          });
          sendClose();
          return;
        }
        const authorizeRes = await fetch(
          `${(import.meta.env.VITE_API_URL || '')}/api/delegate/authorize-sign`,
          withSessionCredential({
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              authorizationContextToken: previewToken,
              // Sol CRITICAL-1: /authorize-sign requires the preview
              // approval token so it cannot independently accept a
              // different selection or sign different bytes.
              previewApprovalToken,
              selectedActionIds,
              protocolVersion: 1,
            }),
          }),
        );
        const authorizeResult = await readReply(
          authorizeRes,
          hasSignResult,
          'authorize-sign failed',
        );
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

      // Exact-byte signing cannot narrow the request: show every parsed
      // action and report the full set rather than a UI-only selection.
      const result = await api.signMessage(key.id, message, origin === '*' ? undefined : origin);
      const effectivePermissions = reviewModel
        ? reviewModel.permissions.map((grant) => ({
            service: grant.service,
            space: grant.space,
            path: grant.path,
            actions: grant.actions.map((action) => action.ability),
          }))
        : undefined;
      sendResponse({
        type: 'openkey:sign:response',
        success: true,
        signature: result.signature,
        address: result.address,
        signedMessage: message,
        selectedActionKeys: reviewModel
          ? reviewModel.permissions.flatMap((grant) => grant.actions.map((action) => action.id))
          : undefined,
        permissions: effectivePermissions,
      });
      sendClose();
    } catch (e: any) {
      if (e instanceof ServerReplyError) unreadableReply(e.status);
      else error = e.message || 'Signing failed';
    } finally {
      signing = false;
    }
  }

  function invalidatePreviewForSelectionEdit() {
    previewSignedMessage = null;
    previewApproved = false;
  }

  // TC-1486: a SIWE-shaped message that does not name the verified requesting
  // origin (or arrives unattributed) is never signed and has no override.
  // Every signing path re-checks this; the server enforces it too.
  const siweRefusal = $derived.by(() => {
    if (!message) return null;
    const check = checkSiweOrigin(message, origin);
    return check.siwe && !check.ok ? check : null;
  });
  let refusalReported = false;
  $effect(() => {
    if (!siweRefusal || refusalReported) return;
    refusalReported = true;
    sendResponse({
      type: 'openkey:sign:response',
      success: false,
      error: { code: 'UNKNOWN', message: `SIWE_ORIGIN_REFUSED: ${siweRefusal.code}` },
    });
  });

  // A reply that cannot be read leaves nothing approved: show the refusal and
  // tell the host once, without any reply content.
  function unreadableReply(status: number) {
    replyFailureStatus = status;
    error = '';
    console.error(`OpenKey: unreadable server reply (HTTP ${status})`);
    sendResponse({ type: 'openkey:sign:response', success: false, error: SERVER_REPLY_ERROR });
  }

  function closeRefused() {
    sendClose();
  }

  function cancel() {
    keyReadGeneration++;
    sendResponse({
      type: 'openkey:sign:response',
      success: false,
      error: { code: 'USER_CANCELLED', message: 'User cancelled' },
    });
    sendClose();
  }

  function sendResponse(data: Record<string, unknown>) {
    // Sol MAJOR-3 (continuation): external-sign approvals bypass the
    // transport's `respond()` shape (which always emits
    // `openkey:sign:response`).
    const isExternalApprove = data.type === 'openkey:externalSign:approve';
    // Route through transport when this was a versioned request AND
    // this is not an external-sign approval.
    if (transport && currentRequestId && messageProtocolVersion !== null && !isExternalApprove) {
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
    if (isExternalApprove && currentRequestId && messageProtocolVersion !== null) {
      const envelope = {
        ...data,
        requestId: currentRequestId,
        protocolVersion: messageProtocolVersion,
      };
      window.parent.postMessage(envelope, origin);
      return;
    }
    window.parent.postMessage(data, origin);
  }

  function sendClose() {
    // Sol MAJOR-4 (continuation): correlate close messages to the active
    // request.
    const closeMsg: Record<string, unknown> = { type: 'openkey:close' };
    if (currentRequestId && messageProtocolVersion !== null) {
      closeMsg.requestId = currentRequestId;
      closeMsg.protocolVersion = messageProtocolVersion;
    }
    window.parent.postMessage(closeMsg, origin);
  }

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
    {#if siweRefusal}
      <SiweOriginRefusal reason={siweRefusal.message} code={siweRefusal.code} onclose={closeRefused} />
    {:else if replyFailureStatus !== null}
      <ServerReplyRefusal status={replyFailureStatus} onclose={closeRefused} />
    {:else if !isAuthenticated}
      <EmbeddedSignIn
        prompt="Sign in to review and sign this message"
        onauthenticated={() => { embedAuthenticated = true; }}
        {passkeysSupported}
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
        <p class="text-sm">{keyError || (requestSealed && keyFetched ? 'Loading selected key...' : 'Please connect first to sign messages.')}</p>
        <Button variant="secondary" size="sm" class="rounded-xl" onclick={cancel}>Cancel</Button>
      </div>
    {:else if reviewModel}
      <!--
        Every parsed protocol renders via the shared approval content. Only
        editable TinyCloud ReCap requests enter the server-preview flow.
      -->
      <!--
        IframeSigningAdapter mirrors the popup adapter — same substantive
        widget completion logic, same transport shape. The route only
        builds the model and hands the adapter its widget transport.
      -->
      <IframeSigningAdapter
        model={reviewModel}
        initialSelection={reviewSelection}
        layoutBlocked={v2 && !layoutReady}
        transport={{
          approving: signing || previewing,
          error: error || layoutError,
          canUseAuthorizeSign: canUseAuthorizeSignFn(),
          previewReady: Boolean(previewToken && previewSignedMessage && previewApprovalToken),
          requestPreview,
          approveAndSign,
          cancel,
          onSelectionEdited: (next) => {
            reviewSelection = next;
          },
          expiry: canUseAuthorizeSignFn() && expiryChangeable
            ? {
                chosenMs: expiryChoiceMs,
                onChange: (ms) => {
                  expiryChoiceMs = ms;
                  invalidatePreviewForSelectionEdit();
                },
              }
            : undefined,
          invalidatePreview: invalidatePreviewForSelectionEdit,
        }}
      />
    {:else}
      <div class="flex flex-col gap-3">
        <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl text-sm" role="alert">
          OpenKey could not build a signing review for this message, so it will not be signed.
        </div>
        <div class="flex gap-2 mt-1">
          <Button variant="secondary" size="sm" class="flex-1 rounded-xl" onclick={cancel}>Cancel</Button>
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
