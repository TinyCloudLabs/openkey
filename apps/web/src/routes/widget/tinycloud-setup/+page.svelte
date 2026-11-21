<!--
  TC-3657 widget page. DRAFT structure/skeleton. Monica owns consent copy; Soren owns final
  interaction + visuals. Business logic lives in `widget-state.ts` (unit-tested); this
  component is the shell + I/O.

  Bobbie 15:16:27Z + 15:42:43Z fixes folded in:
    - F1: Approve button is arm-delayed after mint (1200ms); the state machine transitions
      to `armed` immediately on mint success and the Svelte component disables the button
      until the ARM_DELAY_MS timer fires.
    - F4: `verifiedRequestingOrigin` is captured in state and used for every postMessage
      back, including mint-failed, 429, and publish-failed paths.
    - F7: ticket mint is deferred until the user actually taps Approve.
    - F8 / N4: Approve button copy uses the browser-verified origin in `armed` phase.
    - N3: WebAuthn assertion wired via `confirmWithPasskey` (same path as every other
      OpenKey managed-key approval, `apps/web/src/lib/approval-passkey.ts`). ALWAYS +
      SENSITIVE owners now complete the flow instead of failing closed.
    - N6: `startMint` sets `mintInFlight`; a second tap is refused while a mint is live.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { confirmWithPasskey, PasskeyPromptError, type ApprovalPasskeyOffer } from '$lib/approval-passkey';
  import {
    applyDecline,
    applyMintResult,
    applyPublishResult,
    applySyn,
    approveButtonLabel,
    claimLabel,
    initialState,
    startMint,
    type PostBackEnvelope,
    type WidgetState,
  } from './widget-state';

  export let data: { embeddedRefusalMessage: string | null };

  let state: WidgetState = initialState(data.embeddedRefusalMessage);
  let opener: Window | null = null;
  let armed = false;
  const ARM_DELAY_MS = 1200;

  function postBack(envelope: PostBackEnvelope) {
    if (!state.replyTargetOrigin) return;
    try { opener?.postMessage(envelope, state.replyTargetOrigin); } catch { /* opener closed */ }
  }

  function closeSoon() { setTimeout(() => { try { window.close(); } catch { /* no-op */ } }, 300); }

  async function requestMint() {
    if (!state.verifiedRequestingOrigin || state.mintInFlight) return;
    state = startMint(state);
    try {
      const response = await fetch('/api/tinycloud-setup/mint-ticket', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ requestingOrigin: state.verifiedRequestingOrigin }),
      });
      if (!response.ok) {
        const retryAfterSeconds = response.status === 429 ? Number(response.headers.get('retry-after') ?? '60') : undefined;
        const body = await response.json().catch(() => ({})) as { error?: string };
        const update = applyMintResult(state, {
          ok: false, status: response.status, body,
          ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
        });
        state = update.state;
        if (update.postBack) postBack(update.postBack);
        closeSoon();
        return;
      }
      const body = await response.json();
      const update = applyMintResult(state, { ok: true, body });
      state = update.state;
      // F1 arm delay: the button stays disabled for ARM_DELAY_MS after the mint lands so a
      // popup that opens under the cursor can't be double-clicked through the passkey +
      // publish sequence.
      setTimeout(() => { if (state.phase === 'armed') armed = true; }, ARM_DELAY_MS);
    } catch (e) {
      const update = applyMintResult(state, { ok: false, status: 0, body: { error: 'mint_failed' } });
      state = update.state;
      if (update.postBack) postBack(update.postBack);
      closeSoon();
    }
  }

  async function approve() {
    if (!armed || !state.ticket || !state.verifiedRequestingOrigin) return;
    const originalState = state;
    state = { ...state, phase: 'submitting' };
    let passkeyAssertion: unknown = undefined;
    if (state.passkey.required) {
      try {
        const offer: ApprovalPasskeyOffer = { challengeToken: state.passkey.challengeToken, options: state.passkey.options as never };
        passkeyAssertion = await confirmWithPasskey(offer);
      } catch (e) {
        // User dismissed the passkey prompt, or the authenticator failed. Roll back the
        // phase so they can tap Approve again. Do NOT consume the ticket.
        state = { ...originalState, error: e instanceof PasskeyPromptError ? e.message : 'Passkey failed' };
        return;
      }
    }
    try {
      const response = await fetch('/api/tinycloud-setup/publish', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ticket: state.ticket, requestingOrigin: state.verifiedRequestingOrigin, passkeyAssertion }),
      });
      if (!response.ok) {
        const retryAfterSeconds = response.status === 429 ? Number(response.headers.get('retry-after') ?? '60') : undefined;
        const body = await response.json().catch(() => ({})) as { error?: string };
        const update = applyPublishResult(state, {
          ok: false, status: response.status, body,
          ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
        });
        state = update.state;
        if (update.postBack) postBack(update.postBack);
        closeSoon();
        return;
      }
      const body = await response.json();
      const update = applyPublishResult(state, { ok: true, body });
      state = update.state;
      if (update.postBack) postBack(update.postBack);
      closeSoon();
    } catch (e) {
      const update = applyPublishResult(state, { ok: false, status: 0, body: { error: 'publish_failed' } });
      state = update.state;
      if (update.postBack) postBack(update.postBack);
      closeSoon();
    }
  }

  function decline() {
    const update = applyDecline(state);
    state = update.state;
    postBack(update.postBack);
    closeSoon();
  }

  function onMessage(event: MessageEvent) {
    const next = applySyn(state, { origin: event.origin, source: event.source, opener: window.opener, data: event.data });
    if (next === state) return;
    state = next;
    if (opener === null) opener = event.source as Window;
  }

  onMount(() => {
    if (state.phase === 'embedded-refused') return;
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  });

  async function onApproveClick() {
    // The button walks the user through two taps: first a mint (shows "Preparing…" during
    // the arm delay), then after armed → a publish with the WebAuthn prompt.
    if (state.phase === 'review' && !state.mintInFlight && state.ticket === null) {
      await requestMint();
      return;
    }
    if (state.phase === 'armed' && armed) await approve();
  }
</script>

{#if state.phase === 'embedded-refused'}
  <main>
    <h1>Can't continue</h1>
    <p>{data.embeddedRefusalMessage}</p>
  </main>
{:else if state.phase === 'waiting'}
  <main><p>Opening setup…</p></main>
{:else}
  <main>
    <!-- TODO(Monica): final consent copy owned by Monica; current text is DRAFT. -->
    <h1>Set up TinyCloud for this app</h1>

    {#if state.preview}
      <section aria-label="What will be published">
        <dl>
          <dt>Owner</dt><dd><code>{state.preview.subject}</code></dd>
          <dt>Default node</dt><dd><code>{state.preview.nodeDid}</code> at <code>{state.preview.nodeOrigin}</code></dd>
          <dt>Space</dt><dd><code>{state.preview.primarySpaceName}</code></dd>
        </dl>
      </section>
    {/if}

    <section aria-label="Requesting app">
      <p>
        Requested by <strong>{state.verifiedRequestingOrigin ?? ''}</strong>
        {#if claimLabel(state)}
          ({claimLabel(state)})
        {/if}
      </p>
    </section>

    <button
      type="button"
      disabled={state.phase === 'submitting' || state.mintInFlight || (state.phase === 'armed' && !armed)}
      on:click={onApproveClick}
    >
      {approveButtonLabel(state)}
    </button>
    <button type="button" on:click={decline}>Not now</button>

    {#if state.error}
      <p role="alert">{state.error}</p>
    {/if}
  </main>
{/if}
