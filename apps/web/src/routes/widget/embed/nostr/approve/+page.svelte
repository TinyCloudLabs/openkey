<script lang="ts">
  // OpenKey-origin widget page for the Nostr custody + signing flow
  // (secp256k1 Schnorr / BIP-340, NIP-01/NIP-42). Handles both
  // `openkey:nostr:connect:request` (get-or-create identity, optionally a
  // relay-scoped kind:22242 grant) and `openkey:nostr:sign:request` (silent
  // when an active grant covers the request, otherwise an interaction-
  // required consent card followed by a single signing retry).
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
  //    (keyId/pubkey/npub) or a signed event - never a sessionToken, and
  //    never secret/nsec material (which never leaves the API/TEE).
  import { authClient } from '$lib/auth-client';
  import { api, type NostrKey, type SignedNostrEvent, type UnsignedNostrEvent } from '$lib/api';
  import { getSessionToken, isEmbedContext } from '$lib/embed-passkey';
  import { parseCanonicalOrigin, parseNostrRelayUrl, extractRelayTag } from '$lib/nostr-origin';
  import {
    createVersionedIframeTransport,
    type VersionedWidgetRequest,
    type VersionedWidgetTransport,
  } from '$lib/widget-transport';
  import EmbeddedSignIn from '$lib/components/auth/embedded-sign-in.svelte';
  import Button from '$lib/components/ui/button.svelte';

  type NostrErrorCode = 'USER_CANCELLED' | 'TIMEOUT' | 'INTERACTION_REQUIRED' | 'UNAUTHORIZED' | 'UNKNOWN';
  type Mode = 'connect' | 'sign' | null;
  type Step = 'idle' | 'sign-in' | 'consent' | 'working' | 'error';

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
  let nostrKey = $state<NostrKey | null>(null);

  // signEvent() request state
  let pendingKeyId = $state<string | null>(null);
  let pendingEvent = $state<UnsignedNostrEvent | null>(null);

  $effect(() => {
    if (typeof window === 'undefined' || initialized) return;
    initialized = true;
    if (!targetOrigin) return; // fail closed: never send `ready` without a valid target
    transport = createVersionedIframeTransport({
      origin: targetOrigin,
      requestTypes: ['openkey:nostr:connect:request', 'openkey:nostr:sign:request'],
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

  function isValidNostrRequest(request: VersionedWidgetRequest): boolean {
    if (request.type === 'openkey:nostr:connect:request') {
      return request.data.relayUrl === undefined || parseNostrRelayUrl(request.data.relayUrl) !== null;
    }
    return typeof request.data.keyId === 'string'
      && !!request.data.keyId
      && isPlausibleEvent(request.data.event);
  }

  function handleTransportRequest(request: VersionedWidgetRequest) {
    if (mode !== null) return;
    currentRequestId = request.requestId;
    const data = request.data;

    if (request.type === 'openkey:nostr:connect:request') {
      mode = 'connect';
      pendingRelayUrl = parseNostrRelayUrl(data.relayUrl) ?? undefined;
      void startConnect();
      return;
    }

    if (request.type === 'openkey:nostr:sign:request') {
      mode = 'sign';
      pendingKeyId = data.keyId as string;
      pendingEvent = data.event as UnsignedNostrEvent;
      void startSign();
    }
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
      if (pendingRelayUrl) {
        await api.nostr.createGrant(nostrKey.id, {
          clientOrigin: targetOrigin,
          kinds: [22242],
          relayUrl: pendingRelayUrl,
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
      const relayUrl = pendingEvent.kind === 22242 ? extractRelayTag(pendingEvent) : null;
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
    failSignCancelled();
  }

  function failSignCancelled() {
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

  function onAuthenticated() {
    embedAuthenticated = true;
    if (mode === 'connect') void runConnect();
    else if (mode === 'sign') void attemptSign(false);
  }

  function eventSummary(evt: UnsignedNostrEvent | null): { title: string; detail: string } {
    if (!evt) return { title: '', detail: '' };
    if (evt.kind === 22242) {
      return { title: 'Authenticate to relay', detail: extractRelayTag(evt) || 'an unknown relay' };
    }
    if (evt.kind === 9) {
      const preview = evt.content.length > 240 ? `${evt.content.slice(0, 240)}…` : evt.content;
      return { title: 'Send a channel message', detail: preview || '(empty message)' };
    }
    return { title: `Sign event (kind ${evt.kind})`, detail: '' };
  }
</script>

<div bind:this={contentEl} class="flex flex-col gap-4 bg-[#fafafa] p-4 rounded-2xl">
  <div class="flex flex-col items-center gap-3">
    <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-surface-800 to-surface-900 flex items-center justify-center shadow-sm">
      <svg class="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h.01M15 12h.01M21 12c0 4.97-4.03 9-9 9-1.6 0-3.1-.42-4.4-1.15L3 21l1.15-3.6A8.96 8.96 0 013 12c0-4.97 4.03-9 9-9s9 4.03 9 9z" />
      </svg>
    </div>
    <h1 class="text-lg font-semibold text-surface-900">
      {mode === 'sign' ? 'Sign Nostr Event' : 'Connect Nostr Identity'}
    </h1>
  </div>

  <div class="bg-white border border-surface-200 rounded-2xl shadow-sm p-5">
    {#if step === 'error'}
      <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl text-sm" role="alert">
        {error}
      </div>
    {:else if step === 'sign-in'}
      <EmbeddedSignIn
        prompt={mode === 'sign' ? 'Sign in to approve this signing request' : 'Sign in or create an account to connect'}
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
        <div class="flex gap-2 mt-1">
          <Button variant="secondary" size="sm" class="flex-1 rounded-xl" onclick={cancelSign}>Cancel</Button>
          <Button size="sm" class="flex-1 rounded-xl" onclick={approveSign}>Approve</Button>
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
