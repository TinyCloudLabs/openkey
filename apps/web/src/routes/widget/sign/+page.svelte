<script lang="ts">
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import PopupSigningAdapter from '$lib/components/signing/popup-signing-adapter.svelte';
  import { originAuthority, requesterDisplayName } from '$lib/requester-display';
  import { validatePreviewSelection } from '$lib/preview-review';
  import {
    parseCapabilityReview,
    parseSiweChainId,
    defaultSelection,
    annotateAppScopedGrants,
    type CapabilityReviewModel,
    type DeclaredAppScope,
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
  // Sol MAJOR-9 (per-request immutable state): once a request lands we
  // never mutate its bound state. A follow-up transport request creates
  // a NEW logical request. If a versioned request is already in-flight
  // (approval pending / signing running / previewing), overlapping
  // requests are refused server-side by our own state machine so the
  // response cannot escape to the wrong parent.
  let requestSealed = $state(false);
  // Sol CRITICAL-1 (distinct final approval): the popup MUST call
  // /authorize-sign-preview so the user sees the EXACT bytes the server
  // would sign, then approves again before /authorize-sign consumes the
  // token. `previewSignedMessage` holds the server-returned candidate;
  // `previewToken` is the opaque authorization-context token bound at
  // /authorize-sign-prepare time. Both are cleared when the user edits
  // the selection so the flow returns to preview+approve.
  let previewSignedMessage = $state<string | null>(null);
  let previewToken = $state<string | null>(null);
  // Sol CRITICAL-1: preview-approval token that seals the exact
  // (selection, signedMessage) pair. /authorize-sign requires this token.
  let previewApprovalToken = $state<string | null>(null);
  let previewing = $state(false);
  let previewApproved = $state(false);
  // Sol MAJOR-3 (continuation): when the SDK passes `externalSign: true`
  // on the sign request, the widget MUST NOT call /authorize-sign at
  // approval time. Instead it emits an `openkey:externalSign:approve`
  // response with the preview payload so the SDK can invoke the user's
  // wallet on the previewed bytes and complete /authorize-sign with an
  // externalSignature.
  let externalSignMode = $state(false);

  // Shared capability-review state — the SigningApproval component uses this
  // when the request looks like a TinyCloud SIWE-ReCap. Legacy plain
  // signMessage requests still render via the legacy fallback below.
  let reviewModel = $state<CapabilityReviewModel | null>(null);
  // Tracks which caller message initialized `reviewSelection`. Server
  // metadata and exact-byte preview updates rebuild the display model but
  // must not silently reset a user's narrowed selection.
  let reviewSourceMessage = $state<string | null>(null);
  let reviewSelection = $state(new Set<string>());
  let reviewEditing = $state(false);
  // Presentation envelope forwarded by the SDK. Display-only. The widget
  // NEVER treats it as verified — trust is decided by the server prepare
  // response.
  let requestPresentation = $state<Record<string, unknown> | null>(null);
  // Server-decided trust for the presentation envelope. Populated after
  // /authorize-sign-prepare returns. Starts null so we fail closed to the
  // `unsigned` model until the server responds.
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
        // Sol MAJOR-2: origin-bound app-scope declarations. Only used
        // as DISPLAY-only enrichment for KV/secret grants; never
        // widens authority.
        declaredAppScope?: DeclaredAppScope;
      }
    | null
  >(null);

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
    // Sol MAJOR-9 (immutable per-request state): once a request lands
    // we refuse to overwrite it with another. A sibling call from the
    // same parent (or a re-post from a stuck SDK) MUST NOT hijack the
    // in-flight approval — we respond to it with a dedicated error via
    // the transport so the caller gets a clear rejection rather than a
    // silent drop.
    if (requestSealed) {
      console.warn(
        '[sign widget] refusing overlapping request; existing request:',
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
    // Sol MAJOR-3 (continuation): capture the externalSign flag from the
    // sign request. The widget renders the SAME SigningApproval UI in
    // both modes; only the "approve" behaviour differs.
    externalSignMode = data.externalSign === true;
    // Capture the caller-supplied presentation envelope. It has already
    // been validated + size-bounded by the widget transport; here we only
    // stash the resulting object so the review model can render it. Trust
    // decision is still deferred to the server (see /authorize-sign-prepare).
    requestPresentation =
      data.presentation && typeof data.presentation === 'object'
        ? (data.presentation as Record<string, unknown>)
        : null;
    // Server-decided trust is not known yet — starts null, populated after
    // the first /authorize-sign-prepare call. Editing/reset invalidates
    // the preview but keeps the trust decision (which is bound into the
    // authorization context, not into the selection).
    serverMetadataTrust = null;
    serverVerifiedManifest = null;
    reviewModel = null;
    reviewSourceMessage = null;
    reviewSelection = new Set();
    keyFetched = false;
    // Reset preview state — a new request always starts with no bound
    // preview. Editing selection also clears these fields.
    previewSignedMessage = null;
    previewToken = null;
    previewApprovalToken = null;
    previewApproved = false;
    requestSealed = true;
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
      // Sol MAJOR-9: refuse overlapping legacy request too.
      if (requestSealed) {
        console.warn('[sign widget] refusing overlapping legacy request');
        return;
      }
      console.log('[sign widget] sign request received, message:', event.data.message?.substring(0, 100), 'keyId:', event.data.keyId);
      message = event.data.message;
      messageProtocolVersion = incomingProtocolVersion;
      messageJwk = event.data.jwk ?? null;
      messageHost = typeof event.data.host === 'string' ? event.data.host : '';
      keyId = event.data.keyId || null;
      // Legacy path: envelope forwarding. The legacy path has weaker
      // origin/version guarantees, so we only accept `presentation` as
      // display-only and never upgrade trust off of it — the server
      // prepare call remains the sole trust authority.
      requestPresentation =
        event.data.presentation && typeof event.data.presentation === 'object'
          ? event.data.presentation
          : null;
      serverMetadataTrust = null;
      serverVerifiedManifest = null;
      keyFetched = false; // Reset so effect can run
      requestSealed = true;

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
    // Sol MAJOR-8 (requester + origin/domain facts wired into model):
    // compute REAL warnings rather than hard-coding them to false. The
    // SIWE `domain` line and the postMessage origin's hostname MUST
    // agree — otherwise the widget is presenting a review from one
    // relying party while the parent frame is a different origin.
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
    // Envelope + server-decided trust wiring. The envelope came from the
    // SDK (display-only). Trust is authoritative from the server prepare
    // response (`serverMetadataTrust`); until that lands we fail closed
    // to `unsigned`. `requesterVerified` is true ONLY when the server
    // returned `origin-bound` or `verified`.
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
    // Trust: server-authoritative when set, otherwise `unsigned`. NEVER
    // let the envelope claim its own trust status.
    const effectiveTrust = serverMetadataTrust ?? {
      status: 'unsigned' as const,
      reason: envelope
        ? 'awaiting server verification of manifest envelope'
        : 'no manifest supplied',
    };
    // Manifest facts displayed: prefer the server's verified fields when
    // the server upgraded trust; fall back to the caller-echoed envelope
    // for `unsigned` display (which still surfaces the digest so the user
    // sees WHAT the caller claimed — the trust label prevents any
    // implication of verification).
    //
    // Sol MAJOR-4: compute provenance ALONGSIDE the display strings so
    // the shared component can render each caller-echoed field with a
    // visible "unverified" hint. Never mark a fall-back envelope value
    // as origin-bound.
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
    // The summary requester must never be a caller-controlled presentation
    // name. Until the server origin-binds the manifest, show the browser
    // authority; keep the caller's claimed name only in Advanced details.
    const displayName = requesterDisplayName(manifestNameFromServer, origin);
    // Sol MAJOR-1 (final continuation): the widget MUST NOT infer a
    // "verified requester" identity from data that is not the requester's
    // own declaration. Prior code marked origin-bound requests as verified
    // AND used `key.address` — the USER's signing identity — as the
    // requester address for the classifier. That's wrong on two axes:
    //   1. `key.address` is not the requester. It is the signer. Using it
    //      as the classifier's `requesterAddress` claims the requesting
    //      app is the same principal as the signer, which produces false
    //      "own-app" classifications for every grant against the signer's
    //      spaces.
    //   2. Origin-bind proves the manifest was served from a specific
    //      origin. It does NOT prove that any declared identity (address,
    //      DID, or otherwise) belongs to that origin. Upgrading
    //      `requesterVerified` on origin-bind alone would let the widget
    //      confidently render a caller's untrusted `displayName` /
    //      identity as if OpenKey vouched for it.
    //
    // Correct semantics: leave `requesterVerified=false` and
    // `requesterAddress=null` unless an identity has been explicitly
    // declared by the manifest AND independently verified. The classifier
    // then falls back to its safe path (treats grants on the signer's
    // spaces as cross-app), which is the honest report.
    const requesterVerifiedNow = false;
    const requesterAddressForClassifier: string | null = null;
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
          // Sol minor: pass the origin-bound `appId` when the server
          // verified it. Never fall back to the caller-echoed envelope
          // for this field — it is DISPLAYED as a distinct trusted
          // identifier in the Advanced-details disclosure.
          appId: serverVerifiedManifest?.appId ?? null,
          // Sol MAJOR-4: pass manifest name + ID together with their
          // honest provenance. The Advanced-details disclosure uses the
          // provenance to render a visible "unverified" hint on caller-
          // supplied fields; a caller MUST NOT be able to slip a name
          // past the operator as if OpenKey had verified it.
          manifestName,
          manifestNameProvenance,
          manifestId: displayManifestId,
          manifestIdProvenance,
          manifestDigest: displayManifestDigest,
          domainWarning: domainMismatchForModel,
          // Sol MAJOR-8: wildcard origin means the widget cannot prove
          // the parent's identity — surface it as a warning rather than
          // silently accepting.
          originWarning: originIsWildcard,
        },
        requesterAddress: requesterAddressForClassifier,
        requesterVerified: requesterVerifiedNow,
      });
      // Sol MAJOR-2: app-scoped-secret trust rule. When the SERVER
      // origin-bound the manifest (`origin-bound` or `verified` trust
      // status) AND that manifest declared a scoped secret matching
      // the grant's exact (secretName, scope, actions) triple, add a
      // compact "app-scoped" metadata label. In every other case the
      // grant is left untouched — including its severity, which
      // metadata may NEVER lower. See app-scope.ts for the rule.
      const nextReviewModel = annotateAppScopedGrants(
        model,
        serverVerifiedManifest?.declaredAppScope,
      );
      // Keep the final decision in this same shared model. Only the raw
      // bytes change after preview; categorized grants and edit/reset stay
      // visible through the approval that actually signs them.
      reviewModel = previewSignedMessage
        ? { ...nextReviewModel, rawMessage: previewSignedMessage }
        : nextReviewModel;
      if (reviewSourceMessage !== message) {
        reviewSelection = defaultSelection(reviewModel);
        reviewSourceMessage = message;
      }
    } catch {
      reviewModel = null;
    }
  });

  // Helper: is this request eligible for server-authoritative narrowing?
  // Never true for `malformed-recap` — that protocol is non-signable.
  function canUseAuthorizeSignFn(): boolean {
    return (
      messageProtocolVersion !== null &&
      messageProtocolVersion >= 1 &&
      origin !== '*' &&
      reviewModel !== null &&
      reviewModel.protocol === 'tinycloud-siwe-recap'
    );
  }

  // Fail-closed: a `malformed-recap` model must never reach any signing
  // path. Legacy exact-byte signMessage() would otherwise let a caller
  // sign SIWE bytes whose ReCap payload the widget could not decode —
  // silently dropping the capability payload the request intended to
  // grant. This function guards the Approve action for the legacy path;
  // the authorizeTinyCloud path already refuses via canUseAuthorizeSignFn.
  function isProtocolSignable(): boolean {
    if (!reviewModel) return true; // legacy plain-message flow
    return reviewModel.protocol !== 'malformed-recap';
  }

  // Convert the current review selection to canonical action IDs.
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

  // Sol CRITICAL-1: preview step. Issues (or re-uses) an authorization
  // context via /authorize-sign-prepare, then calls
  // /authorize-sign-preview to obtain the EXACT bytes the server would
  // sign for the current selection. The user must approve the preview
  // before /authorize-sign consumes the token.
  async function requestPreview(): Promise<void> {
    if (!key || !message) return;
    if (!canUseAuthorizeSignFn()) return;
    previewing = true;
    error = '';
    previewApproved = false;
    try {
      // Issue a bound context if we don't have one yet. We keep the same
      // token across selection edits until the user approves — token TTL
      // is 5 minutes, so a fresh /authorize-sign-prepare per selection
      // change would burn tokens without benefit.
      let token = previewToken;
      if (!token) {
        // Envelope + reported-origin forwarding. `origin` is the widget's
        // configured parent origin — the server treats it as advisory
        // only; the trust decision hinges on the SSRF-guarded well-known
        // manifest fetch matching the envelope's declared digest. Passing
        // wildcard origin skips the origin-bind attempt server-side.
        const reportedOriginForPrepare =
          origin && origin !== '*' && origin.startsWith('https://') ? origin : undefined;
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
              presentation: requestPresentation ?? undefined,
              reportedOrigin: reportedOriginForPrepare,
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
        if (!token) {
          throw new Error('authorize-sign-prepare did not return a context token');
        }
        previewToken = token;
        // Adopt the server-decided trust decision + verified manifest
        // fields. The review model rebuild is reactive on these state
        // fields so the UI relabels itself once trust arrives.
        if (
          prepareResult.metadataTrust &&
          typeof prepareResult.metadataTrust === 'object' &&
          typeof prepareResult.metadataTrust.status === 'string' &&
          typeof prepareResult.metadataTrust.reason === 'string'
        ) {
          const status = prepareResult.metadataTrust.status;
          if (status === 'verified' || status === 'origin-bound' || status === 'unsigned') {
            serverMetadataTrust = {
              status,
              reason: prepareResult.metadataTrust.reason,
            };
          }
        }
        if (
          prepareResult.verifiedManifest &&
          typeof prepareResult.verifiedManifest === 'object'
        ) {
          const vm = prepareResult.verifiedManifest as Record<string, unknown>;
          // Sol MAJOR-2: adopt the origin-bound app-scope declarations.
          // The server extracted these from the ALREADY-digest-matched
          // well-known manifest; the widget forwards them as
          // display-only enrichment to `annotateAppScopedGrants`.
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
              .map(s => ({
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
              .map(p => ({
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
      const requestedActionIds = currentSelectedActionIds();
      const previewRes = await fetch(
        `${(import.meta.env.VITE_API_URL || '')}/api/delegate/authorize-sign-preview`,
        {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            authorizationContextToken: token,
            selectedActionIds: requestedActionIds,
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
      // Sol CRITICAL-1: capture the sealed preview-approval token so
      // /authorize-sign can be gated on it.
      if (typeof previewResult.previewApprovalToken !== 'string' || !previewResult.previewApprovalToken) {
        throw new Error('authorize-sign-preview did not return a previewApprovalToken — server is out of date');
      }
      reviewSelection = validatePreviewSelection(previewResult, requestedActionIds);
      previewSignedMessage = previewResult.signedMessage;
      previewApprovalToken = previewResult.previewApprovalToken;
    } catch (e: any) {
      error = e.message || 'Preview failed';
      // On failure, invalidate any stored token so the next attempt gets
      // a fresh one — the server may have expired the token or rejected
      // the immutable-fields digest.
      previewToken = null;
      previewSignedMessage = null;
      previewApprovalToken = null;
    } finally {
      previewing = false;
    }
  }

  // Sol CRITICAL-1: distinct final approval. The preview bytes are what
  // gets signed; the token binding + preview digest are the sole
  // authorities. This is the ONLY function that calls /authorize-sign
  // and consumes the token.
  async function approveAndSign() {
    if (!key || !message) return;
    // Fail-closed: refuse to sign a malformed ReCap regardless of path.
    if (!isProtocolSignable()) {
      error =
        'Refusing to sign: this SIWE carries a capability payload that could not be decoded. The signer would otherwise silently drop the caller’s ReCap.';
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
        // Sol MAJOR-3 (continuation): external-key mode. The wallet lives
        // in the parent frame, not here. Hand back the preview payload
        // and let the SDK invoke the wallet + call /authorize-sign.
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
          {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              authorizationContextToken: previewToken,
              // Sol CRITICAL-1: the sealed preview-approval token is
              // required so /authorize-sign cannot independently accept
              // a different selection or sign different bytes.
              previewApprovalToken,
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
        // Defence in depth: the server must have signed the exact bytes
        // the user approved. If /authorize-sign returned different bytes
        // than the preview showed, refuse.
        if (authorizeResult.signedMessage !== previewSignedMessage) {
          throw new Error(
            'Server signed bytes differ from the previewed bytes — refusing to accept',
          );
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

  // Called by SigningApproval when the selection changes. Clears any
  // approved preview so the user must review + approve the new bytes.
  function invalidatePreviewForSelectionEdit() {
    previewSignedMessage = null;
    // Also invalidate the preview-approval token: it was bound to the
    // old (selection, bytes) pair. A new preview call must issue a
    // fresh one for the new selection.
    previewApprovalToken = null;
    // Keep the context token: the /authorize-sign-preview call handles a
    // stale selection safely (it re-derives the SIWE without consuming).
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
    // Route through the transport when this was a versioned request
    // (transport was created and we have a correlated requestId).
    // Sol MAJOR-3 (continuation): support both `openkey:sign:response`
    // and `openkey:externalSign:approve` response types. The transport's
    // respond() defaults to `openkey:sign:response`; for the external
    // path we fall through to direct postMessage so the caller receives
    // the correct discriminator.
    const isExternalApprove = data.type === 'openkey:externalSign:approve';
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
    // Sol MAJOR-3 (continuation): external-sign approvals bypass the
    // transport's `respond()` shape (which always sends
    // `openkey:sign:response`). Emit the correlated envelope directly so
    // the SDK's message listener matches on the correct discriminator.
    if (isExternalApprove && currentRequestId && messageProtocolVersion !== null) {
      const envelope = {
        ...data,
        requestId: currentRequestId,
        protocolVersion: messageProtocolVersion,
      };
      if (window.opener) {
        window.opener.postMessage(envelope, origin);
      } else if (window.parent !== window) {
        window.parent.postMessage(envelope, origin);
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
    // Sol MAJOR-4 (continuation): correlate close messages to the active
    // request so the SDK doesn't tear down a subsequent request when a
    // stale close arrives late.
    const closeMsg: Record<string, unknown> = { type: 'openkey:close' };
    if (currentRequestId && messageProtocolVersion !== null) {
      closeMsg.requestId = currentRequestId;
      closeMsg.protocolVersion = messageProtocolVersion;
    }
    if (window.opener) {
      window.opener.postMessage(closeMsg, origin);
      window.close();
    } else if (window.parent !== window) {
      window.parent.postMessage(closeMsg, origin);
    }
  }

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
  {:else if reviewModel}
    <!--
      Every parsed protocol renders through the shared approval content.
      Editable TinyCloud ReCap requests use the server-preview step; plain
      SIWE and legacy exact-byte requests approve directly, while malformed
      ReCaps remain disabled by the shared component.
    -->
    <!--
      PopupSigningAdapter is a substantive adapter that owns the review
      selection/editing state, the approve decision (preview vs
      exact-byte), the cancel wiring, and the invalidate-preview-on-edit
      glue. The route only builds the model and hands the adapter a
      widget-specific transport. The exact adapter used in production is
      the exact adapter the parity test mounts — including the preview
      routing decision and the invalidation-on-selection-change.
    -->
    <PopupSigningAdapter
      model={reviewModel}
      initialSelection={reviewSelection}
      transport={{
        approving: signing || previewing,
        error,
        canUseAuthorizeSign: canUseAuthorizeSignFn(),
        previewReady: Boolean(previewToken && previewSignedMessage && previewApprovalToken),
        requestPreview,
        approveAndSign,
        cancel,
        onSelectionEdited: (next) => {
          // Route-side state mirror kept in sync so downstream fetches
          // (e.g. sendResponse) still see the up-to-date selection.
          reviewSelection = next;
        },
        invalidatePreview: invalidatePreviewForSelectionEdit,
      }}
    />
  {:else}
    <!--
      Parser failure is fail-closed. `parseCapabilityReview` normally returns
      a model even for arbitrary legacy text, so reaching this branch means
      OpenKey cannot safely construct the shared approval content.
    -->
    <div class="flex flex-col gap-4 flex-1">
      <Card class="bg-red-500/10 border-red-500 text-red-500 p-4" role="alert">
        OpenKey could not build a signing review for this message, so it will not be signed.
      </Card>

      <div class="flex gap-3 mt-auto">
        <Button variant="secondary" class="flex-1" onclick={cancel}>Cancel</Button>
      </div>
    </div>
  {/if}
</div>
