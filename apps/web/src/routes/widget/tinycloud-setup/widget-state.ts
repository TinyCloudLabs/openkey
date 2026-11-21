// TC-3657 widget business logic, extracted from `+page.svelte` so three invariants have
// direct unit tests: the browser-verified origin is captured once and carried through
// every reply; the ticket mint fires on the user's tap, not on the opener's syn; the
// Approve-button copy names the browser-verified origin and never the caller-asserted
// name. The `armed` phase lives in state so `approveButtonLabel` reads it; `mintInFlight`
// is the flag that makes the "no double-tap burns two mints" invariant testable without a
// Svelte component. The component is a thin shell over this state machine.

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
  /** True from the moment the user taps Approve until the mint settles. The button reads
   *  this to refuse a second tap; a successful mint ends it. */
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

/** The Approve button's copy. In `armed` it names the browser-verified origin (never the
 *  caller-asserted app name). `submitting` reads "Setting up…"; `review` / no-origin read
 *  "Preparing…". */
export function approveButtonLabel(state: WidgetState): string {
  if (state.phase === 'submitting') return 'Setting up…';
  if (state.phase === 'armed' && state.verifiedRequestingOrigin) return `Set up for ${state.verifiedRequestingOrigin}`;
  return 'Preparing…';
}

/** The claimed name is a caller assertion; the UI must label it. Returns null when the
 *  app made no name claim. */
export function claimLabel(state: WidgetState): string | null {
  if (!state.claim.name) return null;
  return `It calls itself "${state.claim.name}". OpenKey hasn't checked that name.`;
}

/** The "who asked" sentence shown next to the preview. Returns null until the browser-
 *  verified origin has been captured. */
export function requesterLine(state: WidgetState): string | null {
  if (!state.verifiedRequestingOrigin) return null;
  return `${state.verifiedRequestingOrigin} asked to set up your TinyCloud.`;
}

/** Map an API refusal reason to the visible error line. The 429 rate-limit line is set at
 *  the applyMintResult / applyPublishResult call site; everything else goes through this
 *  map. Raw reasons like `mint_failed` / `publish_failed` / `setup_unavailable` never
 *  appear on screen. */
export function visibleErrorForReason(reason: string | undefined): string {
  if (reason === 'setup_unavailable') return "Setup isn't available right now. Try again later.";
  return "Setup didn't finish. Try again.";
}

/** Fold a `syn` message from the opener into state. Only the first capture sticks; later
 *  messages from a different origin cannot change the verified origin or opener. Does NOT
 *  mint the ticket; the owner's hourly quota is only spent on their tap. */
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

/** Mark the mint request as in-flight. The Svelte click handler calls this before the
 *  fetch so a second tap sees `mintInFlight === true` and refuses. */
export function startMint(state: WidgetState): WidgetState {
  return { ...state, mintInFlight: true };
}

/** Fold a mint response (success, 429, or failure) into state. Every error path keeps
 *  `verifiedRequestingOrigin` set so the caller can post the result back. */
export function applyMintResult(
  state: WidgetState,
  result:
    | { ok: true; body: MintResponseBody }
    | { ok: false; status: number; body: { error?: string }; retryAfterSeconds?: number },
): { state: WidgetState; postBack: PostBackEnvelope | null } {
  if (result.ok) {
    return {
      state: { ...state, ticket: result.body.ticket, preview: result.body.preview, passkey: result.body.passkey, phase: 'armed', mintInFlight: false },
      postBack: null,
    };
  }
  if (result.status === 429) {
    const reason = 'rate_limited';
    return {
      state: { ...state, phase: 'declined', mintInFlight: false, error: 'Too many tries. Try again later.' },
      postBack: {
        type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason,
        ...(result.retryAfterSeconds !== undefined ? { retryAfter: result.retryAfterSeconds } : {}),
      },
    };
  }
  const reason = result.body.error ?? 'mint_failed';
  return {
    state: { ...state, phase: 'declined', mintInFlight: false, error: visibleErrorForReason(reason) },
    postBack: { type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason },
  };
}

/** Fold a publish response. All error paths carry `verifiedRequestingOrigin`, so the
 *  caller can post back. Success and declined reach `done` / `declined`. */
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
      state: { ...state, phase: 'declined', error: 'Too many tries. Try again later.' },
      postBack: {
        type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason: 'rate_limited',
        ...(result.retryAfterSeconds !== undefined ? { retryAfter: result.retryAfterSeconds } : {}),
      },
    };
  }
  const reason = result.body.error ?? 'publish_failed';
  return {
    state: { ...state, phase: 'declined', error: visibleErrorForReason(reason) },
    postBack: { type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason },
  };
}

export function applyDecline(state: WidgetState): { state: WidgetState; postBack: PostBackEnvelope } {
  return {
    state: { ...state, phase: 'declined' },
    postBack: { type: 'openkey:tinycloud-setup:response', v: 1, status: 'declined' },
  };
}
