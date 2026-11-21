<!--
  TC-3657 widget page. The business logic lives in `widget-state.ts` (unit-tested); this
  component is the shell + I/O only. Copy strings come from `widget-state.ts` helpers
  (`approveButtonLabel`, `claimLabel`, `requesterLine`) so they stay locked in tests.

  Invariants:
    - The Approve button is disabled until an arm delay after mint (`ARM_DELAY_MS`), so a
      popup that opens under the cursor can't be double-clicked through the passkey +
      publish sequence.
    - `verifiedRequestingOrigin` is captured once from the opener's postMessage and used
      for every reply, including the rate-limited, mint-failed, and publish-failed paths.
    - Ticket mint happens on the user's tap, not on the opener's `syn` — so a malicious
      page cannot burn the owner's hourly mint quota by firing messages.
    - `mintInFlight` refuses a second tap while a mint is live.
    - The button names the browser-verified origin, never the caller-asserted app name.
    - WebAuthn assertion uses `confirmWithPasskey` (same path as every other managed-key
      approval); dismissal rolls back to `armed` so the user can retry; the ticket is not
      consumed on a passkey failure.
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
    requesterLine,
    startMint,
    type PostBackEnvelope,
    type WidgetState,
  } from './widget-state';

  export let data: { embeddedRefusalMessage: string | null };

  let state: WidgetState = initialState(data.embeddedRefusalMessage);
  let opener: Window | null = null;
  let armed = false;
  const ARM_DELAY_MS = 1200;

  /** Strip the `did:pkh:eip155:<chain>:` prefix so the preview shows just the owner address. */
  function addressFromSubject(subject: string): string {
    const match = /^did:pkh:eip155:\d+:(.+)$/.exec(subject);
    return match ? match[1] : subject;
  }

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
        state = { ...originalState, error: e instanceof PasskeyPromptError ? e.message : "Your passkey didn't confirm. Try again." };
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
    <h1>Set up your TinyCloud</h1>

    {#if requesterLine(state)}
      <p>{requesterLine(state)}</p>
    {/if}
    {#if claimLabel(state)}
      <p>{claimLabel(state)}</p>
    {/if}

    {#if state.preview}
      <dl>
        <dt>Account</dt><dd>{addressFromSubject(state.preview.subject)}</dd>
        <dt>Stored on</dt><dd>{state.preview.nodeOrigin}</dd>
        <dt>Space</dt><dd>{state.preview.primarySpaceName}</dd>
      </dl>
    {/if}

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
