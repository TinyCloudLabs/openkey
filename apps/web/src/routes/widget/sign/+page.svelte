<script lang="ts">
  import { page } from '$app/stores';
  import { untrack } from 'svelte';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { ARCHIVED_KEY_MESSAGE, autoSelectKey, signingKeyChoices } from '$lib/delegate-key-selection';
  import { parseSIWE } from '$lib/siwe-parser';
  import KeyPicker from '$lib/components/keys/KeyPicker.svelte';
  import SigningKeyRefusal from '$lib/components/signing/signing-key-refusal.svelte';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import { passkeysSupportedFromParams, withPasskeysFlag } from '$lib/passkey-support';
  import PopupSigningAdapter from '$lib/components/signing/popup-signing-adapter.svelte';
  import { originAuthority, requesterDisplayName } from '$lib/requester-display';
  import { requestedActionIds, selectionFromPreview } from '$lib/widget-selection';
  import { expiryAt, siweExpiration } from '$lib/approval-expiry';
  import { PREVIEW_EXPIRED_MESSAGE, signingPreviewDeadline, type SigningPreview } from '$lib/signing-preview';
  import {
    parseCapabilityReview,
    parseSiweChainId,
    defaultSelection,
    annotateAppScopedGrants,
    type CapabilityReviewModel,
    type DeclaredAppScope,
    checkSiweOrigin,
    isSiweShaped,
  } from '@openkey/capability-review';
  import SiweOriginRefusal from '$lib/components/signing/siwe-origin-refusal.svelte';
  import ServerReplyRefusal from '$lib/components/signing/server-reply-refusal.svelte';
  import { hasSignResult, hasText, readReply, ServerRefusalError, ServerReplyError, SERVER_REPLY_ERROR, terminalRefusal } from '$lib/server-reply';
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
  // The key the request named; null when the app named none and the account's keys decide.
  let requestedKeyId: string | null = null;
  let key = $state<EthereumKey | null>(null);
  let keyChoices = $state<EthereumKey[]>([]);
  let keyChoicesLoaded = $state(false);
  let keyChoicesSessionId: string | undefined;
  // Why no key could be used. 'missing': no key of this account fits (Sign out lets another account continue; the
  // app is told NO_KEY). 'transient': the key, key list or session could not be read (Try again; the app is told
  // USER_CANCELLED, so it keeps its connection).
  let keyProblem = $state<'missing' | 'transient' | null>(null);
  let keyReadGeneration = 0;
  const expectedAddress = $derived(parseSIWE(message)?.message.address.toLowerCase() ?? null);
  let loading = $state(true);
  let signing = $state(false);
  let error = $state('');
  // The HTTP status of a reply that could not be read; shown in Advanced details only.
  let replyFailureStatus = $state<number | null>(null);
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
  // Background previews seal the current selection and exact bytes before Approve is enabled.
  let heldPreview = $state<SigningPreview | null>(null);
  const previewSignedMessage = $derived(heldPreview?.signedMessage ?? null);
  let previewToken = $state<string | null>(null);
  let contextDeadline = 0;
  let previewRevision = $state(0);
  let previewStopped = false;
  let previewing = $state(false);
  // TC-2272: how long from approval the user chose; null keeps the app's own expiry.
  let expiryChoiceMs = $state<number | null>(null);
  // Sol MAJOR-3 (continuation): when the SDK passes `externalSign: true`
  // on the sign request, the widget MUST NOT call /authorize-sign at
  // approval time. Instead it emits an `openkey:externalSign:approve`
  // response with the preview payload so the SDK can invoke the user's
  // wallet on the previewed bytes and complete /authorize-sign with an
  // externalSignature.
  let externalSignMode = $state(false);
  let expiryChangeable = $state(false);

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
  const requester = originAuthority(origin);
  const reconnectHint = `Go back to ${requester || 'the requesting app'} and connect again to choose a key.`;
  const passkeysSupported = passkeysSupportedFromParams($page.url.searchParams);

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
      previewStopped = true;
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
    requestedKeyId = keyId;
    // Sol MAJOR-3 (continuation): capture the externalSign flag from the
    // sign request. The widget renders the SAME SigningApproval UI in
    // both modes; only the "approve" behaviour differs.
    externalSignMode = data.externalSign === true;
    // TC-2272: only an SDK that accepts a different signed expiry sends this; without it the
    // approval shows no expiry control and the app's own expiry is signed.
    expiryChangeable = data.expiryChangeable === true;
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
    heldPreview = null;
    previewToken = null;
    contextDeadline = 0;
    previewRevision++;
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
  // The session the loaded key was read with: a key never outlives it (as the iframe's keyOwnerSessionId).
  let keySessionId: string | undefined;
  $effect(() => {
    if ($session.data && keyId && !keyFetched && !key) {
      keyFetched = true;
      const selectedId = keyId;
      const sessionId = $session.data.session?.id;
      const generation = ++keyReadGeneration;
      api.getKey(selectedId).then(result => {
        if (generation !== keyReadGeneration) return;
        if ($session.data?.session?.id !== sessionId) {
          error = 'Signing session changed. Reconnect to choose a key.';
          dropPreviewContext();
          keyProblem = 'transient';
          return;
        }
        if (result.key.archivedAt) {
          error = ARCHIVED_KEY_MESSAGE;
          keyProblem = 'missing';
          key = null;
          return;
        }
        key = result.key;
        keySessionId = sessionId;
      }).catch((failure: unknown) => {
        if (generation !== keyReadGeneration) return;
        error = 'Selected key could not be loaded. Reconnect to choose a key.';
        keyProblem = keyNotInAccount(failure) ? 'missing' : 'transient';
      });
    }
  });

  // Another account signed in while a key was loaded (or the session ended): drop the key before it can sign.
  $effect(() => {
    if (!key || $session.data?.session?.id === keySessionId) return;
    keyReadGeneration++;
    key = null;
    untrack(dropPreviewContext);
    error = 'Signing session changed. Reconnect to choose a key.';
    keyProblem = 'transient';
  });

  function chooseSigningKey(selected: EthereumKey) {
    if ($session.data?.session?.id !== keyChoicesSessionId) {
      error = 'Signing session changed. Reconnect to choose a key.';
      dropPreviewContext();
      keyProblem = 'transient';
      keyChoices = [];
      return;
    }
    keyFetched = true;
    keyId = selected.id;
    key = selected;
    keySessionId = keyChoicesSessionId;
  }

  $effect(() => {
    if (!$session.data || !requestSealed || keyId || keyChoicesLoaded) return;
    keyChoicesLoaded = true;
    loading = true;
    const sessionId = $session.data.session?.id;
    const address = expectedAddress;
    const requestMessage = message;
    const keyType = externalSignMode ? 'EXTERNAL' : 'MANAGED';
    const generation = ++keyReadGeneration;
    api.listKeys().then(({ keys }) => {
      if (generation !== keyReadGeneration) return;
      if ($session.data?.session?.id !== sessionId) {
        error = 'Signing session changed. Reconnect to choose a key.';
        dropPreviewContext();
        keyProblem = 'transient';
        return;
      }
      keyChoicesSessionId = sessionId;
      // A SIWE names its signer; one whose address cannot be read fits no key rather than any key.
      keyChoices = !address && isSiweShaped(requestMessage) ? [] : signingKeyChoices(keys, address, keyType);
      if (!keyChoices.length) {
        error = 'Requested signing key is not available. Reconnect to choose a key.';
        keyProblem = 'missing';
        return;
      }
      const selected = autoSelectKey(keyChoices, address);
      if (selected) chooseSigningKey(selected);
    }).catch(() => {
      if (generation !== keyReadGeneration) return;
      error = 'Signing keys could not be loaded. Reconnect to choose a key.';
      keyProblem = 'transient';
    }).finally(() => { if (generation === keyReadGeneration) loading = false; });
  });

  /** A key read the server refused (404/403): the key is not this account's, so reading again cannot help. */
  function keyNotInAccount(failure: unknown): boolean {
    return failure instanceof Error && 'status' in failure && (failure.status === 404 || failure.status === 403);
  }

  // A preview context is issued to the account that was signed in: a key or session reset discards it, as a new request
  // does, so the next preview is prepared for the account now signed in.
  function dropPreviewContext() {
    heldPreview = null;
    previewToken = null;
    contextDeadline = 0;
    previewRevision++;
  }

  /** Read again from the start of key selection: the named key, or the account's keys when the request named none. */
  function retryKey() {
    keyReadGeneration++;
    key = null;
    dropPreviewContext();
    error = '';
    keyProblem = null;
    keyChoices = [];
    keyId = requestedKeyId;
    keyFetched = false;
    keyChoicesLoaded = false;
    loading = false;
  }

  // Same as the connect widget's Sign out; Sign In then returns to this page, and the SDK sends the request again.
  // The session ends before key selection restarts, so nothing is read with the old one.
  async function signOutForKey() {
    await authClient.signOut();
    retryKey();
  }

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
      requestedKeyId = keyId;
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
      // Do not construct a model with a placeholder key. The no-key
      // branches show loading, a key choice, or a key refusal until the
      // key loads and this effect fires again.
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
    // to `unsigned`.
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
      // Before the preview the access lines show the chosen time (from now); after it, the sealed bytes' own.
      reviewModel = previewSignedMessage
        ? { ...nextReviewModel, rawMessage: previewSignedMessage, expiry: siweExpiration(previewSignedMessage) ?? nextReviewModel.expiry }
        : expiryChoiceMs !== null
          ? { ...nextReviewModel, expiry: expiryAt(expiryChoiceMs) }
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
    return requestedActionIds(reviewModel, reviewSelection);
  }

  // A stable value avoids refetching when display-only metadata rebuilds the review model.
  const previewInput = $derived.by(() =>
    key && canUseAuthorizeSignFn() && !siweRefusal
      ? JSON.stringify([currentRequestId, key.id, message,
          [...currentSelectedActionIds()].sort(), expiryChoiceMs])
      : null,
  );

  $effect(() => {
    const input = previewInput;
    const revision = previewRevision;
    if (input !== null) untrack(() => { void requestPreview(input, revision); });
  });

  $effect(() => {
    const preview = heldPreview;
    if (!preview) return;
    const timer = setTimeout(() => {
      if (heldPreview === preview && !signing && !previewStopped) invalidatePreviewForSelectionEdit();
    }, Math.max(0, preview.deadline - performance.now()));
    return () => clearTimeout(timer);
  });

  function currentPreview(): SigningPreview | null {
    const preview = heldPreview;
    return !previewStopped && !signing && !previewing && preview &&
      preview.input === previewInput && preview.revision === previewRevision &&
      performance.now() < preview.deadline ? preview : null;
  }

  // Prepare the current selection in the background; only Approve consumes its sealed token.
  async function requestPreview(input: string, revision: number): Promise<void> {
    if (refused) return;
    if (!key || !message) return;
    if (siweRefusal) return;
    if (!canUseAuthorizeSignFn()) return;
    if (signing || previewStopped) return;
    const isCurrent = () => !previewStopped && revision === previewRevision && input === previewInput;
    const selectedIds = currentSelectedActionIds();
    const requestedExpiry = expiryChoiceMs === null ? null : expiryAt(expiryChoiceMs);
    previewing = true;
    error = '';
    try {
      // Issue a bound context if we don't have one yet. We keep the same
      // token across selection edits until the user approves — token TTL
      // is 5 minutes, so a fresh /authorize-sign-prepare per selection
      // change would burn tokens without benefit.
      let token = performance.now() < contextDeadline ? previewToken : null;
      if (!token) {
        // Envelope + reported-origin forwarding. `origin` is the widget's
        // configured parent origin — the server treats it as advisory
        // only; the trust decision hinges on the SSRF-guarded well-known
        // manifest fetch matching the envelope's declared digest. Passing
        // wildcard origin skips the origin-bind attempt server-side.
        const reportedOriginForPrepare =
          origin && origin !== '*' && origin.startsWith('https://') ? origin : undefined;
        const prepareStarted = performance.now();
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
              requestOrigin: origin === '*' ? undefined : origin,
              // Bound into the authorization context: the server refuses a changed expiry unless the app opted in.
              ...(expiryChangeable ? { expiryChangeable: true } : {}),
            }),
          },
        );
        const prepareResult = await readReply(
          prepareRes,
          (body) => hasText(body, 'authorizationContextToken'),
          'authorize-sign-prepare failed',
        );
        if (!isCurrent()) return;
        contextDeadline = signingPreviewDeadline(prepareResult.expiresAt, prepareRes.headers.get('Date'), prepareStarted);
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
      if (!isCurrent()) return;
      const previewStarted = performance.now();
      const previewRes = await fetch(
        `${(import.meta.env.VITE_API_URL || '')}/api/delegate/authorize-sign-preview`,
        {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            authorizationContextToken: token,
            selectedActionIds: selectedIds,
            // TC-2272: only when the user changed it; the app's own expiry stays the default.
            ...(requestedExpiry === null ? {} : { expirationTime: requestedExpiry }),
          }),
        },
      );
      const previewResult = await readReply(
        previewRes,
        (body) => hasText(body, 'signedMessage', 'previewApprovalToken'),
        'authorize-sign-preview failed',
      );
      if (!isCurrent()) return;
      if (typeof previewResult.signedMessage !== 'string' || !previewResult.signedMessage) {
        throw new Error('authorize-sign-preview did not return signedMessage');
      }
      // Sol CRITICAL-1: capture the sealed preview-approval token so
      // /authorize-sign can be gated on it.
      if (typeof previewResult.previewApprovalToken !== 'string' || !previewResult.previewApprovalToken) {
        throw new Error('authorize-sign-preview did not return a previewApprovalToken — server is out of date');
      }
      selectionFromPreview(previewResult, selectedIds);
      const deadline = Math.min(contextDeadline,
        signingPreviewDeadline(previewResult.previewApprovalExpiresAt, previewRes.headers.get('Date'), previewStarted));
      if (deadline <= performance.now()) throw new Error(PREVIEW_EXPIRED_MESSAGE);
      heldPreview = {
        input, revision, authorizationContextToken: token,
        previewApprovalToken: previewResult.previewApprovalToken,
        signedMessage: previewResult.signedMessage, selectedActionIds: selectedIds, deadline,
      };
    } catch (e: any) {
      if (!isCurrent()) return;
      if (e instanceof ServerRefusalError) refuse(e);
      else if (e instanceof ServerReplyError) unreadableReply(e.status);
      else if (!refuse(e)) error = e.message || 'Preview failed';
      // On failure, invalidate any stored token so the next attempt gets
      // a fresh one — the server may have expired the token or rejected
      // the immutable-fields digest.
      previewToken = null;
      heldPreview = null;
      contextDeadline = 0;
    } finally {
      if (isCurrent()) previewing = false;
    }
  }

  // The click captures one current preview; later state changes cannot replace its bytes or token.
  async function approveAndSign() {
    if (refused) return;
    if (!key || !message) return;
    if (signing || previewStopped) return;
    if (siweRefusal) {
      error = siweRefusal.message;
      return;
    }
    // Fail-closed: refuse to sign a malformed ReCap regardless of path.
    if (!isProtocolSignable()) {
      error =
        'Refusing to sign: this SIWE carries a capability payload that could not be decoded. The signer would otherwise silently drop the caller’s ReCap.';
      return;
    }
    const approved = canUseAuthorizeSignFn() ? currentPreview() : null;
    if (canUseAuthorizeSignFn() && !approved) {
      if (!previewing) invalidatePreviewForSelectionEdit();
      return;
    }
    signing = true;
    error = '';
    try {
      if (approved) {
        const { authorizationContextToken, previewApprovalToken, signedMessage } = approved;
        const selectedActionIds = [...approved.selectedActionIds];
        // Sol MAJOR-3 (continuation): external-key mode. The wallet lives
        // in the parent frame, not here. Hand back the preview payload
        // and let the SDK invoke the wallet + call /authorize-sign.
        if (externalSignMode) {
          sendResponse({
            type: 'openkey:externalSign:approve',
            success: true,
            authorizationContextToken,
            previewApprovalToken,
            signedMessage,
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
              authorizationContextToken,
              // Sol CRITICAL-1: the sealed preview-approval token is
              // required so /authorize-sign cannot independently accept
              // a different selection or sign different bytes.
              previewApprovalToken,
              selectedActionIds,
              protocolVersion: 1,
            }),
          },
        );
        const authorizeResult = await readReply(
          authorizeRes,
          hasSignResult,
          'authorize-sign failed',
        );
        // Defence in depth: the server must have signed the exact bytes
        // the user approved. If /authorize-sign returned different bytes
        // than the preview showed, refuse.
        if (authorizeResult.signedMessage !== signedMessage) {
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
      const result = await api.signMessage(key.id, message, origin === '*' ? undefined : origin);
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
      if (e instanceof ServerRefusalError) refuse(e);
      else if (e instanceof ServerReplyError) unreadableReply(e.status);
      else if (!refuse(e)) error = e.message || 'Signing failed';
    } finally {
      signing = false;
      if (approved && !previewStopped) {
        previewToken = null;
        contextDeadline = 0;
        heldPreview = null;
      }
    }
  }

  function invalidatePreviewForSelectionEdit() {
    heldPreview = null;
    previewRevision++;
  }

  function retryPreview() {
    if (!canUseAuthorizeSignFn() || signing || previewing || heldPreview || previewStopped || !error) return;
    invalidatePreviewForSelectionEdit();
  }

  // TC-1486: a SIWE-shaped message that does not name the verified requesting
  // origin (or arrives unattributed) is never signed and has no override.
  // Every signing path below re-checks this; the server enforces it too.
  const siweRefusal = $derived.by(() => {
    if (!message) return null;
    const check = checkSiweOrigin(message, origin);
    return check.siwe && !check.ok ? check : null;
  });
  let refusalReported = false;
  $effect(() => {
    if (!siweRefusal || refusalReported) return;
    refusalReported = true;
    // Tell the requester right away so its promise settles; the message is
    // generic on purpose (it may be an unattributed '*' recipient).
    sendResponse({
      type: 'openkey:sign:response',
      success: false,
      error: { code: 'UNKNOWN', message: `SIWE_ORIGIN_REFUSED: ${siweRefusal.code}` },
    });
  });

  // A reply that cannot be read leaves nothing approved: show the refusal and
  // tell the host once, without any reply content.

  let refusalMessage = $state<string | null>(null);

  function unreadableReply(status: number) {
    replyFailureStatus = status;
    error = '';
    console.error(`OpenKey: unreadable server reply (HTTP ${status})`);
    sendResponse({ type: 'openkey:sign:response', success: false, error: SERVER_REPLY_ERROR });
  }

  // TC-2457: a refusal the server decides from the request itself cannot change on retry. Show the reason, keep
  // Approve disabled, and tell the host once so the app that asked does not wait for ever. Nothing else is sent: the
  // identifier carries no server text.
  let refused = $state(false);
  let refusalSent = false;
  function refuse(failure: unknown): boolean {
    const terminal = terminalRefusal(failure);
    if (!terminal) return false;
    refusalMessage = terminal.text;
    refused = true;
    error = terminal.text;
    previewToken = null;
    heldPreview = null;
    contextDeadline = 0;
    if (!refusalSent) {
      refusalSent = true;
      sendResponse({ type: 'openkey:sign:response', success: false, error: { code: 'UNKNOWN', message: terminal.hostMessage } });
    }
    return true;
  }

  function closeRefused() {
    sendClose();
  }

  function reconnect() {
    if (!refusalSent) {
      sendResponse({
        type: 'openkey:sign:response',
        success: false,
        // Only a key this account lacks drops the app's connection (NO_KEY); a read that may work later does not.
        error: { code: keyProblem === 'missing' ? 'NO_KEY' : 'USER_CANCELLED', message: `${error} ${reconnectHint}` },
      });
    }
    sendClose();
  }

  function cancel() {
    if (!refusalSent) {
      sendResponse({
        type: 'openkey:sign:response',
        success: false,
        error: !key && keyProblem === 'missing'
          ? { code: 'NO_KEY', message: error }
          : { code: 'USER_CANCELLED', message: 'User cancelled' },
      });
    }
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
    previewStopped = true;
    heldPreview = null;
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
    <h1 class="text-xl font-semibold text-surface-900">Sign Message</h1>
    <button
      class="bg-transparent border-none text-surface-600 text-2xl cursor-pointer p-0 leading-none hover:text-surface-900 transition-colors"
      onclick={cancel}
    >
      &times;
    </button>
  </header>

  {#if siweRefusal}
    <SiweOriginRefusal reason={siweRefusal.message} code={siweRefusal.code} onclose={closeRefused} />
  {:else if replyFailureStatus !== null}
    <ServerReplyRefusal status={replyFailureStatus} onclose={closeRefused} />
  {:else if !$session.data}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p class="mb-4">Sign in to sign messages</p>
      <Button href={withPasskeysFlag(`/auth/login?redirect=/widget/sign?origin=${encodeURIComponent(origin)}`, passkeysSupported)}>Sign In</Button>
    </div>
  {:else if loading}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      Loading...
    </div>
  {:else if !key && keyChoices.length > 1}
    <KeyPicker
      keys={keyChoices}
      {expectedAddress}
      onselect={chooseSigningKey}
      listHeading="Select a key to sign:"
      primaryHeading="Sign with your primary key:"
    />
    <Button variant="secondary" class="mt-4" onclick={cancel}>Cancel</Button>
  {:else if !key && error}
    <SigningKeyRefusal
      message={error}
      {requester}
      onreconnect={reconnect}
      onsignout={keyProblem === 'missing' ? signOutForKey : undefined}
      onretry={keyProblem === 'transient' ? retryKey : undefined}
    />
  {:else if !key}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400" data-testid="signing-key-loading">
      <p>Loading...</p>
      <Button variant="secondary" class="mt-4" onclick={cancel}>Cancel</Button>
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
        approving: signing,
        host: messageHost,
        error,
        approveBlockedReason: refusalMessage,
        refused,
        canUseAuthorizeSign: canUseAuthorizeSignFn(),
        previewReady: currentPreview() !== null,
        retryPreview: canUseAuthorizeSignFn() && error && !refused && !signing && !previewing && !heldPreview ? retryPreview : undefined,
        approveAndSign,
        cancel,
        onSelectionEdited: (next) => {
          // Route-side state mirror kept in sync so downstream fetches
          // (e.g. sendResponse) still see the up-to-date selection.
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
