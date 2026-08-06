<script lang="ts">
  // OpenKey-origin widget page for the Nostr custody flow (secp256k1
  // Schnorr / BIP-340, NIP-01/NIP-42/NIP-44/NIP-59). Handles:
  //  - `openkey:nostr:connect:request` - get-or-create identity, optionally
  //    approving a full requested capability set (kinds + operations, with
  //    a relay binding for destination-bound kinds) in one consent.
  //  - `openkey:nostr:sign:request` - silent when an active grant covers
  //    the request, otherwise an interaction-required consent card with
  //    per-kind copy followed by a single signing retry.
  //  - `openkey:nostr:{encrypt,decrypt,wrap,unwrap}:request` - named crypto
  //    operations (NIP-44 encrypt/decrypt, NIP-59 gift wrap/unwrap), each
  //    independently granted with operation-specific consent copy.
  //
  // Security invariants for this route specifically:
  //  - `targetOrigin` is parsed once via `parseCanonicalOrigin` and is either
  //    an exact http(s) origin or `null`. It is NEVER `'*'`. If it is `null`
  //    this page never sends or accepts any postMessage traffic.
  //  - Every incoming `message` event is checked against both
  //    `event.origin === targetOrigin` and `event.source === window.parent`
  //    before its payload is read.
  //  - Every outgoing `postMessage` call targets `targetOrigin` explicitly.
  //  - Response payloads to the parent only ever carry public identity data
  //    (keyId/pubkey/npub), signed events, ciphertext, or plaintext the user
  //    authorized this app to obtain - never a sessionToken, and never
  //    secret/nsec material (which never leaves the API/TEE).
  import { authClient } from '$lib/auth-client';
  import {
    api,
    type NostrKey,
    type NostrRumor,
    type SignedNostrEvent,
    type UnsignedNostrEvent,
  } from '$lib/api';
  import { getSessionToken, isEmbedContext } from '$lib/embed-passkey';
  import {
    parseCanonicalOrigin,
    parseNostrRelayUrl,
    extractRelayTag,
    deriveRelayUrlForGrant,
  } from '$lib/nostr-origin';
  import {
    DESTINATION_BOUND_NOSTR_KINDS,
    NOSTR_KIND_COPY,
    NOSTR_OPERATION_COPY,
    SUPPORTED_NOSTR_KINDS,
    isSupportedNostrOperation,
    type NostrOperationName,
  } from '$lib/nostr-capabilities';
  import {
    createVersionedIframeTransport,
    type VersionedWidgetRequest,
    type VersionedWidgetTransport,
  } from '$lib/widget-transport';
  import EmbeddedSignIn from '$lib/components/auth/embedded-sign-in.svelte';
  import Button from '$lib/components/ui/button.svelte';

  type NostrErrorCode = 'USER_CANCELLED' | 'TIMEOUT' | 'INTERACTION_REQUIRED' | 'UNAUTHORIZED' | 'UNKNOWN';
  type OperationMode = 'encrypt' | 'decrypt' | 'wrap' | 'unwrap';
  type Mode = 'connect' | 'sign' | OperationMode | null;
  type Step = 'idle' | 'sign-in' | 'consent' | 'working' | 'error';

  const PUBKEY_HEX_RE = /^[0-9a-f]{64}$/i;
  const MAX_PLAINTEXT_LENGTH = 4096;
  const MAX_NIP44_PAYLOAD_LENGTH = 87472;
  const MAX_WRAP_RECIPIENTS = 8;

  const OPERATION_BY_MODE: Record<OperationMode, NostrOperationName> = {
    encrypt: 'nip44_encrypt',
    decrypt: 'nip44_decrypt',
    wrap: 'nip59_wrap',
    unwrap: 'nip59_unwrap',
  };

  const RESPONSE_TYPE_BY_MODE: Record<OperationMode, string> = {
    encrypt: 'openkey:nostr:encrypt:response',
    decrypt: 'openkey:nostr:decrypt:response',
    wrap: 'openkey:nostr:wrap:response',
    unwrap: 'openkey:nostr:unwrap:response',
  };

  const session = authClient.useSession();
  const inIframe = typeof window !== 'undefined' && isEmbedContext();

  // Parsed exactly once, never re-derived from a mutable/attacker-influenced
  // source after mount. `null` means "fail closed" - see invariants above.
  const targetOrigin: string | null = typeof window !== 'undefined'
    ? parseCanonicalOrigin(new URL(window.location.href).searchParams.get('origin'))
    : null;

  let embedAuthenticated = $state(typeof window !== 'undefined' && !!getSessionToken());
  const isAuthenticated = $derived(inIframe ? embedAuthenticated : !!$session.data);

  let mode = $state<Mode>(null);
  let step = $state<Step>(targetOrigin ? 'idle' : 'error');
  let error = $state(targetOrigin ? '' : 'This page must be opened by OpenKey with a valid origin.');
  let initialized = $state(false);
  let revealed = $state(false);
  let contentEl = $state<HTMLDivElement | undefined>(undefined);
  let currentRequestId = $state<string | null>(null);
  let transport: VersionedWidgetTransport | null = null;

  // connect() request state
  let pendingRelayUrl = $state<string | undefined>(undefined);
  let pendingKinds = $state<number[]>([]);
  let pendingOperations = $state<NostrOperationName[]>([]);
  let nostrKey = $state<NostrKey | null>(null);

  // signEvent() request state
  let pendingKeyId = $state<string | null>(null);
  let pendingEvent = $state<UnsignedNostrEvent | null>(null);
  let pendingSignRelayHint = $state<string | undefined>(undefined);

  // crypto-operation request state (peerPubkey/plaintext/payload/wrap etc.)
  let pendingOpData = $state<Record<string, unknown> | null>(null);

  $effect(() => {
    if (typeof window === 'undefined' || initialized) return;
    initialized = true;
    if (!targetOrigin) return; // fail closed: never send `ready` without a valid target
    transport = createVersionedIframeTransport({
      origin: targetOrigin,
      requestTypes: [
        'openkey:nostr:connect:request',
        'openkey:nostr:sign:request',
        'openkey:nostr:encrypt:request',
        'openkey:nostr:decrypt:request',
        'openkey:nostr:wrap:request',
        'openkey:nostr:unwrap:request',
      ],
      onRequest: handleTransportRequest,
      onClose: () => {
        step = 'error';
        error = 'Request cancelled';
      },
      validateRequest: isValidNostrRequest,
    });
    transport.emitReady();
  });

  $effect(() => () => transport?.destroy());

  $effect(() => {
    if (!contentEl || !targetOrigin) return;
    const observer = new ResizeObserver(() => {
      transport?.emitResize(contentEl!.scrollHeight);
    });
    observer.observe(contentEl);
    return () => observer.disconnect();
  });

  function reveal() {
    if (revealed || !targetOrigin) return;
    revealed = true;
    transport?.emit('openkey:nostr:show');
  }

  function isPlausibleEvent(value: unknown): value is UnsignedNostrEvent {
    if (!value || typeof value !== 'object') return false;
    const e = value as Record<string, unknown>;
    return typeof e.kind === 'number'
      && typeof e.created_at === 'number'
      && typeof e.content === 'string'
      && Array.isArray(e.tags)
      && typeof e.pubkey === 'string';
  }

  function isPlausibleSignedEvent(value: unknown): value is SignedNostrEvent {
    if (!isPlausibleEvent(value)) return false;
    const e = value as unknown as Record<string, unknown>;
    return typeof e.id === 'string' && typeof e.sig === 'string';
  }

  function hasKeyId(data: Record<string, unknown>): boolean {
    return typeof data.keyId === 'string' && !!data.keyId;
  }

  function isValidNostrRequest(request: VersionedWidgetRequest): boolean {
    const data = request.data;
    switch (request.type) {
      case 'openkey:nostr:connect:request': {
        if (data.relayUrl !== undefined && parseNostrRelayUrl(data.relayUrl) === null) return false;
        if (data.kinds !== undefined) {
          if (!Array.isArray(data.kinds) || data.kinds.length === 0 || data.kinds.length > SUPPORTED_NOSTR_KINDS.size) return false;
          if (!data.kinds.every((k) => typeof k === 'number' && SUPPORTED_NOSTR_KINDS.has(k))) return false;
          // Destination-bound kinds can only be granted against a relay.
          if (data.kinds.some((k: number) => DESTINATION_BOUND_NOSTR_KINDS.has(k)) && parseNostrRelayUrl(data.relayUrl) === null) return false;
        }
        if (data.operations !== undefined) {
          if (!Array.isArray(data.operations) || data.operations.length === 0 || data.operations.length > 4) return false;
          if (!data.operations.every(isSupportedNostrOperation)) return false;
        }
        return true;
      }
      case 'openkey:nostr:sign:request':
        return hasKeyId(data)
          && isPlausibleEvent(data.event)
          && (data.relayUrl === undefined || parseNostrRelayUrl(data.relayUrl) !== null);
      case 'openkey:nostr:encrypt:request':
        return hasKeyId(data)
          && typeof data.peerPubkey === 'string' && PUBKEY_HEX_RE.test(data.peerPubkey)
          && typeof data.plaintext === 'string' && data.plaintext.length > 0 && data.plaintext.length <= MAX_PLAINTEXT_LENGTH;
      case 'openkey:nostr:decrypt:request':
        return hasKeyId(data)
          && typeof data.peerPubkey === 'string' && PUBKEY_HEX_RE.test(data.peerPubkey)
          && typeof data.payload === 'string' && data.payload.length > 0 && data.payload.length <= MAX_NIP44_PAYLOAD_LENGTH;
      case 'openkey:nostr:wrap:request':
        return hasKeyId(data)
          && typeof data.content === 'string' && data.content.length > 0 && data.content.length <= MAX_PLAINTEXT_LENGTH
          && Array.isArray(data.recipients)
          && data.recipients.length >= 1 && data.recipients.length <= MAX_WRAP_RECIPIENTS
          && data.recipients.every((r) => typeof r === 'string' && PUBKEY_HEX_RE.test(r))
          && (data.createdAt === undefined || typeof data.createdAt === 'number');
      case 'openkey:nostr:unwrap:request':
        return hasKeyId(data) && isPlausibleSignedEvent(data.wrap);
      default:
        return false;
    }
  }

  function handleTransportRequest(request: VersionedWidgetRequest) {
    if (mode !== null) return;
    currentRequestId = request.requestId;
    const data = request.data;

    if (request.type === 'openkey:nostr:connect:request') {
      mode = 'connect';
      pendingRelayUrl = parseNostrRelayUrl(data.relayUrl) ?? undefined;
      pendingKinds = Array.isArray(data.kinds) ? (data.kinds as number[]) : [];
      pendingOperations = Array.isArray(data.operations) ? (data.operations as NostrOperationName[]) : [];
      void startConnect();
      return;
    }

    if (request.type === 'openkey:nostr:sign:request') {
      mode = 'sign';
      pendingKeyId = data.keyId as string;
      pendingEvent = data.event as UnsignedNostrEvent;
      pendingSignRelayHint = parseNostrRelayUrl(data.relayUrl) ?? undefined;
      void startSign();
      return;
    }

    const opMode = (
      {
        'openkey:nostr:encrypt:request': 'encrypt',
        'openkey:nostr:decrypt:request': 'decrypt',
        'openkey:nostr:wrap:request': 'wrap',
        'openkey:nostr:unwrap:request': 'unwrap',
      } as Record<string, OperationMode>
    )[request.type];
    if (!opMode) return;
    mode = opMode;
    pendingKeyId = data.keyId as string;
    pendingOpData = data;
    void startOperation();
  }

  // ===== connect() =====

  async function startConnect() {
    if (!isAuthenticated) {
      step = 'sign-in';
      reveal();
      return;
    }
    await runConnect();
  }

  async function runConnect() {
    step = 'working';
    reveal();
    try {
      const { key } = await api.nostr.getOrCreateKey();
      nostrKey = key;
      step = 'consent';
    } catch (e: any) {
      failConnect('UNKNOWN', e?.message || 'Failed to load your Nostr identity');
    }
  }

  async function approveConnect() {
    if (!nostrKey || !targetOrigin) return;
    step = 'working';
    try {
      // Back-compat: a bare `relayUrl` with no explicit kinds keeps the
      // original behavior of a relay-auth-only grant.
      const kinds = pendingKinds.length > 0 ? pendingKinds : (pendingRelayUrl ? [22242] : []);
      if (kinds.length > 0 || pendingOperations.length > 0) {
        await api.nostr.createGrant(nostrKey.id, {
          clientOrigin: targetOrigin,
          kinds,
          operations: pendingOperations,
          ...(pendingRelayUrl ? { relayUrl: pendingRelayUrl } : {}),
        });
      }
      respondConnect(true);
    } catch (e: any) {
      failConnect('UNKNOWN', e?.message || 'Failed to authorize this app');
    }
  }

  function cancelConnect() {
    respondConnect(false, { code: 'USER_CANCELLED', message: 'User cancelled' });
  }

  function failConnect(code: NostrErrorCode, message: string) {
    error = message;
    step = 'error';
    respondConnect(false, { code, message });
  }

  function respondConnect(success: boolean, err?: { code: NostrErrorCode; message: string }) {
    if (!currentRequestId) return;
    transport?.respond(
      'openkey:nostr:connect:response',
      currentRequestId,
      success,
      success && nostrKey
        ? { keyId: nostrKey.id, pubkey: nostrKey.pubkeyHex, npub: nostrKey.npub }
        : { error: err ?? { code: 'UNKNOWN', message: 'Connect failed' } },
    );
  }

  // ===== signEvent() =====

  async function startSign() {
    if (!isAuthenticated) {
      step = 'sign-in';
      reveal();
      return;
    }
    await attemptSign(false);
  }

  async function attemptSign(afterGrant: boolean) {
    if (!pendingKeyId || !pendingEvent || !targetOrigin) return;
    step = 'working';
    try {
      const { event: signed } = await api.nostr.signEvent(pendingKeyId, pendingEvent, targetOrigin);
      respondSign(true, undefined, signed);
    } catch (e: any) {
      if (!afterGrant && e?.status === 403 && e?.message === 'interaction_required') {
        step = 'consent';
        reveal();
        return;
      }
      const code: NostrErrorCode = e?.status === 404 ? 'UNAUTHORIZED' : e?.status === 403 ? 'INTERACTION_REQUIRED' : 'UNKNOWN';
      failSign(code, e?.message || 'Signing failed');
    }
  }

  async function approveSign() {
    if (!pendingKeyId || !pendingEvent || !targetOrigin) return;
    step = 'working';
    try {
      let relayUrl: string | null = null;
      if (DESTINATION_BOUND_NOSTR_KINDS.has(pendingEvent.kind)) {
        relayUrl = deriveRelayUrlForGrant(pendingEvent, pendingSignRelayHint);
        if (!relayUrl) {
          // Fail closed: never create a destination-bound grant without a
          // trustworthy destination to bind it to.
          failSign('UNKNOWN', 'This request did not name the relay it is for.');
          return;
        }
      }
      await api.nostr.createGrant(pendingKeyId, {
        clientOrigin: targetOrigin,
        kinds: [pendingEvent.kind],
        ...(relayUrl ? { relayUrl } : {}),
      });
      // Signing retry: exactly one retry immediately after the grant is
      // created, so approval leads straight to a signed event instead of a
      // second consent round-trip.
      await attemptSign(true);
    } catch (e: any) {
      failSign('UNKNOWN', e?.message || 'Failed to authorize signing');
    }
  }

  function cancelSign() {
    step = 'error';
    error = 'Request cancelled';
    respondSign(false, { code: 'USER_CANCELLED', message: 'User cancelled' });
  }

  function failSign(code: NostrErrorCode, message: string) {
    error = message;
    step = 'error';
    respondSign(false, { code, message });
  }

  function respondSign(success: boolean, err?: { code: NostrErrorCode; message: string }, signed?: SignedNostrEvent) {
    if (!currentRequestId) return;
    transport?.respond(
      'openkey:nostr:sign:response',
      currentRequestId,
      success,
      success && signed
        ? { event: signed }
        : { error: err ?? { code: 'UNKNOWN', message: 'Signing failed' } },
    );
  }

  // ===== named crypto operations =====

  async function startOperation() {
    if (!isAuthenticated) {
      step = 'sign-in';
      reveal();
      return;
    }
    await attemptOperation(false);
  }

  async function callOperationApi(): Promise<Record<string, unknown>> {
    const data = pendingOpData!;
    const keyId = pendingKeyId!;
    const origin = targetOrigin!;
    switch (mode as OperationMode) {
      case 'encrypt': {
        const { ciphertext } = await api.nostr.nip44Encrypt(keyId, {
          clientOrigin: origin,
          peerPubkey: data.peerPubkey as string,
          plaintext: data.plaintext as string,
        });
        return { ciphertext };
      }
      case 'decrypt': {
        const { plaintext } = await api.nostr.nip44Decrypt(keyId, {
          clientOrigin: origin,
          peerPubkey: data.peerPubkey as string,
          payload: data.payload as string,
        });
        return { plaintext };
      }
      case 'wrap': {
        const { wraps } = await api.nostr.nip59Wrap(keyId, {
          clientOrigin: origin,
          content: data.content as string,
          recipients: data.recipients as string[],
          ...(typeof data.createdAt === 'number' ? { createdAt: data.createdAt } : {}),
        });
        return { wraps };
      }
      case 'unwrap': {
        const { rumor } = await api.nostr.nip59Unwrap(keyId, {
          clientOrigin: origin,
          wrap: data.wrap as SignedNostrEvent,
        });
        return { rumor: rumor as NostrRumor };
      }
    }
  }

  async function attemptOperation(afterGrant: boolean) {
    if (!mode || mode === 'connect' || mode === 'sign') return;
    if (!pendingKeyId || !pendingOpData || !targetOrigin) return;
    step = 'working';
    try {
      const result = await callOperationApi();
      respondOperation(true, undefined, result);
    } catch (e: any) {
      if (!afterGrant && e?.status === 403 && e?.message === 'interaction_required') {
        step = 'consent';
        reveal();
        return;
      }
      const code: NostrErrorCode = e?.status === 404 ? 'UNAUTHORIZED' : e?.status === 403 ? 'INTERACTION_REQUIRED' : 'UNKNOWN';
      failOperation(code, e?.message || 'Request failed');
    }
  }

  async function approveOperation() {
    if (!mode || mode === 'connect' || mode === 'sign') return;
    if (!pendingKeyId || !targetOrigin) return;
    step = 'working';
    try {
      await api.nostr.createGrant(pendingKeyId, {
        clientOrigin: targetOrigin,
        operations: [OPERATION_BY_MODE[mode as OperationMode]],
      });
      await attemptOperation(true);
    } catch (e: any) {
      failOperation('UNKNOWN', e?.message || 'Failed to authorize this operation');
    }
  }

  function cancelOperation() {
    step = 'error';
    error = 'Request cancelled';
    respondOperation(false, { code: 'USER_CANCELLED', message: 'User cancelled' });
  }

  function failOperation(code: NostrErrorCode, message: string) {
    error = message;
    step = 'error';
    respondOperation(false, { code, message });
  }

  function respondOperation(
    success: boolean,
    err?: { code: NostrErrorCode; message: string },
    result?: Record<string, unknown>,
  ) {
    if (!currentRequestId || !mode || mode === 'connect' || mode === 'sign') return;
    transport?.respond(
      RESPONSE_TYPE_BY_MODE[mode as OperationMode],
      currentRequestId,
      success,
      success && result ? result : { error: err ?? { code: 'UNKNOWN', message: 'Request failed' } },
    );
  }

  function onAuthenticated() {
    embedAuthenticated = true;
    if (mode === 'connect') void runConnect();
    else if (mode === 'sign') void attemptSign(false);
    else if (mode !== null) void attemptOperation(false);
  }

  // ===== consent copy =====

  function eventSummary(evt: UnsignedNostrEvent | null): { title: string; detail: string; sensitive: boolean } {
    if (!evt) return { title: '', detail: '', sensitive: false };
    const copy = NOSTR_KIND_COPY[evt.kind];
    if (evt.kind === 22242) {
      return { title: copy!.title, detail: extractRelayTag(evt) || 'an unknown relay', sensitive: false };
    }
    if (evt.kind === 9 || evt.kind === 40002) {
      const preview = evt.content.length > 240 ? `${evt.content.slice(0, 240)}…` : evt.content;
      return { title: copy!.title, detail: preview || '(empty message)', sensitive: false };
    }
    if (copy) {
      return { title: copy.title, detail: copy.description, sensitive: !!copy.sensitive };
    }
    return { title: `Sign event (kind ${evt.kind})`, detail: '', sensitive: false };
  }

  function operationSummary(current: Mode): { title: string; detail: string; sensitive: boolean } {
    if (!current || current === 'connect' || current === 'sign') return { title: '', detail: '', sensitive: false };
    const copy = NOSTR_OPERATION_COPY[OPERATION_BY_MODE[current as OperationMode]];
    return { title: copy.title, detail: copy.description, sensitive: !!copy.sensitive };
  }

  const requestedCapabilities = $derived.by(() => {
    const entries: { title: string; description: string; sensitive: boolean }[] = [];
    for (const kind of pendingKinds) {
      const copy = NOSTR_KIND_COPY[kind];
      if (copy) entries.push({ title: copy.title, description: copy.description, sensitive: !!copy.sensitive });
    }
    for (const operation of pendingOperations) {
      const copy = NOSTR_OPERATION_COPY[operation];
      if (copy) entries.push({ title: copy.title, description: copy.description, sensitive: !!copy.sensitive });
    }
    return entries;
  });

  const headline = $derived.by(() => {
    if (mode === 'sign') return 'Sign Nostr Event';
    if (mode === 'connect') return 'Connect Nostr Identity';
    if (mode === null) return 'Connect Nostr Identity';
    return operationSummary(mode).title;
  });
</script>

<div bind:this={contentEl} class="flex flex-col gap-4 bg-[#fafafa] p-4 rounded-2xl">
  <div class="flex flex-col items-center gap-3">
    <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-surface-800 to-surface-900 flex items-center justify-center shadow-sm">
      <svg class="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h.01M15 12h.01M21 12c0 4.97-4.03 9-9 9-1.6 0-3.1-.42-4.4-1.15L3 21l1.15-3.6A8.96 8.96 0 013 12c0-4.97 4.03-9 9-9s9 4.03 9 9z" />
      </svg>
    </div>
    <h1 class="text-lg font-semibold text-surface-900">{headline}</h1>
  </div>

  <div class="bg-white border border-surface-200 rounded-2xl shadow-sm p-5">
    {#if step === 'error'}
      <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl text-sm" role="alert">
        {error}
      </div>
    {:else if step === 'sign-in'}
      <EmbeddedSignIn
        prompt={mode === 'connect' ? 'Sign in or create an account to connect' : 'Sign in to approve this request'}
        onauthenticated={onAuthenticated}
      />
    {:else if step === 'consent' && mode === 'connect'}
      <div class="flex flex-col gap-3">
        <p class="text-surface-500 text-sm">Connect your OpenKey Nostr identity to this app.</p>
        {#if nostrKey}
          <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
            <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Identity</span>
            <code class="font-mono text-xs text-surface-900 break-all">{nostrKey.npub}</code>
          </div>
        {/if}
        {#if pendingRelayUrl}
          <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
            <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Community server</span>
            <code class="font-mono text-xs text-surface-900 break-all">{pendingRelayUrl}</code>
          </div>
        {/if}
        {#if requestedCapabilities.length > 0}
          <div class="bg-surface-50 border border-surface-200 rounded-xl p-3 max-h-56 overflow-y-auto">
            <span class="block text-surface-400 text-xs uppercase tracking-wide mb-2">This app will be able to</span>
            <ul class="flex flex-col gap-2">
              {#each requestedCapabilities as capability}
                <li class="text-sm">
                  <span class="text-surface-900 font-medium">{capability.title}</span>
                  {#if capability.sensitive}
                    <span class="ml-1 inline-block align-middle text-[10px] font-semibold uppercase tracking-wide text-amber-700 bg-amber-50 border border-amber-200 rounded px-1">Sensitive</span>
                  {/if}
                  <span class="block text-surface-500 text-xs">{capability.description}</span>
                </li>
              {/each}
            </ul>
          </div>
        {:else if pendingRelayUrl}
          <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
            <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Also allow silent relay authentication</span>
            <code class="font-mono text-xs text-surface-900 break-all">{pendingRelayUrl}</code>
          </div>
        {/if}
        <div class="flex gap-2 mt-1">
          <Button variant="secondary" size="sm" class="flex-1 rounded-xl" onclick={cancelConnect}>Cancel</Button>
          <Button size="sm" class="flex-1 rounded-xl" onclick={approveConnect}>Connect</Button>
        </div>
      </div>
    {:else if step === 'consent' && mode === 'sign'}
      {@const summary = eventSummary(pendingEvent)}
      <div class="flex flex-col gap-3">
        <p class="text-surface-500 text-sm">This app is requesting your approval to sign a Nostr event.</p>
        <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
          <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">{summary.title}</span>
          <span class="text-sm text-surface-900 break-all">{summary.detail}</span>
        </div>
        {#if summary.sensitive}
          <div class="bg-amber-50 border border-amber-200 text-amber-800 px-3 py-2 rounded-xl text-xs">
            This is a moderation or membership action. Approving lets this app perform it silently until the grant expires.
          </div>
        {/if}
        <div class="flex gap-2 mt-1">
          <Button variant="secondary" size="sm" class="flex-1 rounded-xl" onclick={cancelSign}>Cancel</Button>
          <Button size="sm" class="flex-1 rounded-xl" onclick={approveSign}>Approve</Button>
        </div>
      </div>
    {:else if step === 'consent'}
      {@const summary = operationSummary(mode)}
      <div class="flex flex-col gap-3">
        <p class="text-surface-500 text-sm">This app is requesting a private-data operation with your OpenKey identity.</p>
        <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
          <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">{summary.title}</span>
          <span class="text-sm text-surface-900">{summary.detail}</span>
        </div>
        {#if summary.sensitive}
          <div class="bg-amber-50 border border-amber-200 text-amber-800 px-3 py-2 rounded-xl text-xs">
            Approving lets this app read the decrypted content of these messages until the grant expires. Your secret key still never leaves OpenKey.
          </div>
        {/if}
        <div class="flex gap-2 mt-1">
          <Button variant="secondary" size="sm" class="flex-1 rounded-xl" onclick={cancelOperation}>Cancel</Button>
          <Button size="sm" class="flex-1 rounded-xl" onclick={approveOperation}>Approve</Button>
        </div>
      </div>
    {:else}
      <div class="flex flex-col items-center justify-center text-center text-surface-400 py-6">
        <svg class="w-6 h-6 animate-spin text-surface-400 mb-3" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
        </svg>
        <span class="text-sm text-surface-500">Working…</span>
      </div>
    {/if}
  </div>

  <div class="flex items-center justify-center gap-1.5 text-surface-400">
    <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
    <span class="text-xs">Protected by TEE hardware security</span>
  </div>
</div>
