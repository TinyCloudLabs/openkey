// TC-3657 widget business logic, extracted from `+page.svelte` so the invariants Bobbie
// called out (F4 origin-carried-everywhere, F7 mint-on-click-not-on-message,
// F8 button-copy-uses-verified-origin) have their own tests without pulling in a Svelte
// mount harness. The svelte component is a thin shell over this state machine.

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
  // The target origin of every message we send back; always equal to
  // `verifiedRequestingOrigin` when set. Captured here so the Svelte template can bind to it
  // without re-reading the opener's origin each time.
  replyTargetOrigin: string | null;
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
  };
}

/** F8: the copy on the Approve button names the browser-verified origin, never the
 *  caller-asserted app name. The caller's claimed name belongs in the preview, labelled as
 *  a claim. Returns an empty string when the origin isn't known yet (phase=waiting). */
export function approveButtonLabel(state: WidgetState): string {
  if (state.phase === 'submitting') return 'Publishing…';
  if (state.phase === 'review') return 'Preparing…';
  if (!state.verifiedRequestingOrigin) return '';
  return `Approve for ${state.verifiedRequestingOrigin}`;
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
  // Capture once. A second message with a different origin is ignored.
  if (state.verifiedRequestingOrigin !== null && event.origin !== state.verifiedRequestingOrigin) {
    return state;
  }
  const verifiedRequestingOrigin = state.verifiedRequestingOrigin ?? event.origin;
  const next: WidgetState = {
    ...state,
    verifiedRequestingOrigin,
    replyTargetOrigin: verifiedRequestingOrigin,
    claim: event.data.requestingApp ?? {},
    // F7: no ticket mint here.
    phase: state.phase === 'waiting' ? 'review' : state.phase,
  };
  return next;
}

/** Fold a mint response (success, 429, or failure) into state. F4: a 429 or failed response
 *  still has `verifiedRequestingOrigin` set, so the caller can post the result back on the
 *  right origin. */
export function applyMintResult(
  state: WidgetState,
  result:
    | { ok: true; body: MintResponseBody }
    | { ok: false; status: number; body: { error?: string }; retryAfterSeconds?: number },
): { state: WidgetState; postBack: PostBackEnvelope | null } {
  if (result.ok) {
    return {
      state: { ...state, ticket: result.body.ticket, preview: result.body.preview, passkey: result.body.passkey, phase: 'review' },
      postBack: null,
    };
  }
  if (result.status === 429) {
    const reason = 'rate_limited';
    return {
      state: { ...state, phase: 'declined', error: 'Too many setup attempts right now. Try again later.' },
      postBack: {
        type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason,
        ...(result.retryAfterSeconds !== undefined ? { retryAfter: result.retryAfterSeconds } : {}),
      },
    };
  }
  const reason = result.body.error ?? 'mint_failed';
  return {
    state: { ...state, phase: 'declined', error: reason },
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
