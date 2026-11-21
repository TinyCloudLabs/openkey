// TC-3657 widget business logic, extracted from `+page.svelte` so the invariants Bobbie
// called out (F4 origin-carried-everywhere, F7 mint-on-click-not-on-message, F8 button
// copy uses verified origin) have their own tests without pulling in a Svelte mount
// harness. The svelte component is a thin shell over this state machine.
//
// Bobbie 15:42:43Z follow-ups folded in:
//   - N4: `armed` moved into state so `approveButtonLabel` reads it; the Approve/Preparing
//     transition is now observable and covered by the F8 test.
//   - N6: `mintInFlight` flag in state + guard in the Svelte click handler so a double-tap
//     on Approve cannot spend two of the owner's 10/hr mint quota.

export type Phase =
  | 'waiting'
  | 'review'
  | 'armed'
  | 'submitting'
  | 'declined'
  | 'done'
  | 'embedded-refused';

export interface PublishPreview {
  subject: string;
  nodeDid: string;
  nodeOrigin: string;
  space: string;
  primarySpaceName: string;
}

export interface PasskeyOffer {
  challengeToken: string;
  options: unknown;
}

export interface RequestingApp {
  name?: string;
  manifestUrl?: string;
}

export interface MintResponseBody {
  ticket: string;
  ttlMs: number;
  passkey: { required: false } | ({ required: true } & PasskeyOffer);
  preview: PublishPreview;
}

export interface PublishResponseBody {
  status: 'published' | 'already-current' | string;
  subject: string;
}

export interface PostBackEnvelope {
  type: 'openkey:tinycloud-setup:response' | 'openkey:tinycloud-setup:ready';
  v: 1;
  status?: 'published' | 'already-current' | 'unavailable' | 'declined' | string;
  subject?: string;
  reason?: string;
  retryAfter?: number;
}

export interface WidgetState {
  phase: Phase;
  verifiedRequestingOrigin: string | null;
  claim: RequestingApp;
  ticket: string | null;
  preview: PublishPreview | null;
  passkey: { required: false } | ({ required: true } & PasskeyOffer);
  error: string | null;
  replyTargetOrigin: string | null;
  /** N6: true from the moment the user taps Approve until the mint settles. The button
   *  reads this to refuse a second tap; a successful mint ends it. */
  mintInFlight: boolean;
}

export function initialState(embeddedRefusalMessage: string | null): WidgetState {
  return {
    phase: embeddedRefusalMessage ? 'embedded-refused' : 'waiting',
    verifiedRequestingOrigin: null,
    claim: {},
    ticket: null,
    preview: null,
    passkey: { required: false },
    error: embeddedRefusalMessage,
    replyTargetOrigin: null,
    mintInFlight: false,
  };
}

/** F8 + N4: the Approve button's copy. In `armed` it names the browser-verified origin,
 *  never the caller-asserted app name. In `review` (post-syn, pre-arm-delay) it reads
 *  "Preparing…"; in `submitting` it reads "Publishing…". */
export function approveButtonLabel(state: WidgetState): string {
  if (state.phase === 'submitting') return 'Publishing…';
  if (state.phase === 'armed' && state.verifiedRequestingOrigin) return `Approve for ${state.verifiedRequestingOrigin}`;
  // Phase is `review` (post-syn, pre-arm-delay) or we haven't captured the origin yet.
  return 'Preparing…';
}

/** The claimed name is a caller assertion; the UI must label it as such so a crafted
 *  `window.name` or manifest cannot look authoritative. */
export function claimLabel(state: WidgetState): string | null {
  if (!state.claim.name) return null;
  return `the app says its name is "${state.claim.name}" — this is the app's own claim, not verified by OpenKey`;
}

/** Fold a `syn` message from the opener into state. Only the FIRST capture sticks; later
 *  messages from a different origin cannot change the verified origin or opener. F7: this
 *  does NOT mint the ticket — the owner's 10/hour quota is only spent on their tap. */
export function applySyn(state: WidgetState, event: {
  origin: string;
  source: unknown;
  data: { type?: string; v?: number; requestingApp?: RequestingApp };
  opener: unknown;
}): WidgetState {
  if (state.phase === 'embedded-refused') return state;
  if (event.source !== event.opener) return state;
  if (event.data.type !== 'openkey:tinycloud-setup:request' || event.data.v !== 1) return state;
  if (state.verifiedRequestingOrigin !== null && event.origin !== state.verifiedRequestingOrigin) {
    return state;
  }
  const verifiedRequestingOrigin = state.verifiedRequestingOrigin ?? event.origin;
  return {
    ...state,
    verifiedRequestingOrigin,
    replyTargetOrigin: verifiedRequestingOrigin,
    claim: event.data.requestingApp ?? {},
    phase: state.phase === 'waiting' ? 'review' : state.phase,
  };
}

/** Mark the mint request as in-flight (N6). The Svelte click handler calls this before
 *  the fetch so a second tap sees `mintInFlight === true` and refuses. */
export function startMint(state: WidgetState): WidgetState {
  return { ...state, mintInFlight: true };
}

/** Fold a mint response (success, 429, or failure) into state. F4: every error path keeps
 *  `verifiedRequestingOrigin` set so the caller can post the result back. N6: the
 *  in-flight flag clears either way. */
export function applyMintResult(
  state: WidgetState,
  result:
    | { ok: true; body: MintResponseBody }
    | { ok: false; status: number; body: { error?: string }; retryAfterSeconds?: number },
): { state: WidgetState; postBack: PostBackEnvelope | null } {
  if (result.ok) {
    // The post-mint phase is `armed` once the arm-delay timer fires; before that the Svelte
    // component keeps the button disabled by reading `phase === 'review'`. We transition
    // directly to `armed` here because the arm delay is handled in the component for the
    // F1 double-tap-guard, and the state machine shouldn't block tests on real timers.
    return {
      state: { ...state, ticket: result.body.ticket, preview: result.body.preview, passkey: result.body.passkey, phase: 'armed', mintInFlight: false },
      postBack: null,
    };
  }
  if (result.status === 429) {
    const reason = 'rate_limited';
    return {
      state: { ...state, phase: 'declined', mintInFlight: false, error: 'Too many setup attempts right now. Try again later.' },
      postBack: {
        type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason,
        ...(result.retryAfterSeconds !== undefined ? { retryAfter: result.retryAfterSeconds } : {}),
      },
    };
  }
  const reason = result.body.error ?? 'mint_failed';
  return {
    state: { ...state, phase: 'declined', mintInFlight: false, error: reason },
    postBack: { type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason },
  };
}

/** Fold a publish response. F4: all error paths carry `verifiedRequestingOrigin`, so the
 *  caller can post back. Success and declined both reach `done` / `declined` phases. */
export function applyPublishResult(
  state: WidgetState,
  result:
    | { ok: true; body: PublishResponseBody }
    | { ok: false; status: number; body: { error?: string }; retryAfterSeconds?: number },
): { state: WidgetState; postBack: PostBackEnvelope | null } {
  if (result.ok) {
    return {
      state: { ...state, phase: 'done' },
      postBack: { type: 'openkey:tinycloud-setup:response', v: 1, status: result.body.status, subject: result.body.subject },
    };
  }
  if (result.status === 429) {
    return {
      state: { ...state, phase: 'declined' },
      postBack: {
        type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason: 'rate_limited',
        ...(result.retryAfterSeconds !== undefined ? { retryAfter: result.retryAfterSeconds } : {}),
      },
    };
  }
  const reason = result.body.error ?? 'publish_failed';
  return {
    state: { ...state, phase: 'declined' },
    postBack: { type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason },
  };
}

export function applyDecline(state: WidgetState): { state: WidgetState; postBack: PostBackEnvelope } {
  return {
    state: { ...state, phase: 'declined' },
    postBack: { type: 'openkey:tinycloud-setup:response', v: 1, status: 'declined' },
  };
}
