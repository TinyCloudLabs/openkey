// TC-3657 Bobbie F4 + F7 + F8 (15:16:27Z) widget-state tests. One test per regression.
// The state machine is pure; these assertions don't need a Svelte mount harness.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  applyDecline,
  applyMintResult,
  applyPublishResult,
  applySyn,
  approveButtonLabel,
  claimLabel,
  initialState,
  type WidgetState,
} from './widget-state';

const OPENER = {};
const APP_ORIGIN = 'https://thirdparty.example';
const previewBody = {
  ticket: 't',
  ttlMs: 60_000,
  passkey: { required: false } as const,
  preview: {
    subject: 'did:pkh:eip155:1:0x1',
    nodeDid: 'did:key:z1',
    nodeOrigin: 'https://node.example',
    space: 'tinycloud:pkh:eip155:1:0x1:default',
    primarySpaceName: 'default',
  },
};

function synEvent(origin: string, requestingApp: { name?: string; manifestUrl?: string } = {}) {
  return {
    origin, source: OPENER, opener: OPENER,
    data: { type: 'openkey:tinycloud-setup:request', v: 1, requestingApp },
  };
}

describe('widget state', () => {
  // F7: mint is NOT triggered on `syn` from the opener. The state transitions to review
  // but the ticket stays null until an explicit mint call.
  test('F7 regression: syn from opener does not mint a ticket (burn-quota attack)', () => {
    const state = initialState(null);
    const afterSyn = applySyn(state, synEvent(APP_ORIGIN));
    expect(afterSyn.verifiedRequestingOrigin).toBe(APP_ORIGIN);
    expect(afterSyn.phase).toBe('review');
    expect(afterSyn.ticket).toBeNull();
  });

  // F7 strengthens into: a second syn from a different origin cannot overwrite the first.
  test('F7 regression: a second syn from a different origin is ignored', () => {
    const state = initialState(null);
    const first = applySyn(state, synEvent(APP_ORIGIN));
    const attacker = applySyn(first, synEvent('https://attacker.example', { name: 'TakeOver' }));
    expect(attacker.verifiedRequestingOrigin).toBe(APP_ORIGIN);
    expect(attacker.claim).toEqual({});
  });

  // F4: every post-back path carries the verified origin. A rate-limited mint, a failing
  // mint, a 429 publish, and a failing publish all post back a response envelope the SDK
  // can route — which it only can when the widget still knows the origin.
  test('F4 regression: 429 mint still posts back; state keeps verifiedRequestingOrigin', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review' };
    const { state: next, postBack } = applyMintResult(state, { ok: false, status: 429, body: {}, retryAfterSeconds: 42 });
    expect(next.verifiedRequestingOrigin).toBe(APP_ORIGIN);
    expect(next.replyTargetOrigin).toBe(APP_ORIGIN);
    expect(next.phase).toBe('declined');
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason: 'rate_limited', retryAfter: 42 });
  });

  test('F4 regression: failed mint still posts back a reason envelope', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review' };
    const { postBack } = applyMintResult(state, { ok: false, status: 500, body: { error: 'mint_failed' } });
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason: 'mint_failed' });
  });

  test('F4 regression: 429 publish still posts back; state keeps verifiedRequestingOrigin', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'submitting' };
    const { state: next, postBack } = applyPublishResult(state, { ok: false, status: 429, body: {}, retryAfterSeconds: 7 });
    expect(next.verifiedRequestingOrigin).toBe(APP_ORIGIN);
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason: 'rate_limited', retryAfter: 7 });
  });

  test('F4 regression: failed publish still posts back a reason envelope', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'submitting' };
    const { postBack } = applyPublishResult(state, { ok: false, status: 500, body: { error: 'publish_failed' } });
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason: 'publish_failed' });
  });

  test('F4 regression: successful publish posts back status+subject on the right origin', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'submitting' };
    const { postBack, state: next } = applyPublishResult(state, { ok: true, body: { status: 'published', subject: 'did:pkh:eip155:1:0x1' } });
    expect(next.phase).toBe('done');
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'published', subject: 'did:pkh:eip155:1:0x1' });
  });

  test('F4 regression: successful mint stores the ticket + preview; does NOT post back yet', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review' };
    const { state: next, postBack } = applyMintResult(state, { ok: true, body: previewBody });
    expect(next.ticket).toBe('t');
    expect(next.preview?.primarySpaceName).toBe('default');
    expect(postBack).toBeNull();
  });

  test('F4 regression: decline posts back on the verified origin', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review' };
    const { postBack, state: next } = applyDecline(state);
    expect(next.phase).toBe('declined');
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'declined' });
  });

  // F8: the Approve button label uses the verified origin, not the caller-asserted name.
  test('F8 regression: approve button label uses the verified origin, never the claimed app name', () => {
    const state: WidgetState = {
      ...initialState(null),
      verifiedRequestingOrigin: APP_ORIGIN,
      replyTargetOrigin: APP_ORIGIN,
      claim: { name: '<not verified name>' },
      phase: 'armed',
    };
    const label = approveButtonLabel(state);
    expect(label).toBe(`Approve for ${APP_ORIGIN}`);
    expect(label.includes('<not verified name>')).toBe(false);
  });

  test('F8 regression: the claim label labels the name as a claim, not as the app\'s identity', () => {
    const state: WidgetState = {
      ...initialState(null),
      verifiedRequestingOrigin: APP_ORIGIN,
      replyTargetOrigin: APP_ORIGIN,
      claim: { name: 'ClaimedName' },
      phase: 'armed',
    };
    const label = claimLabel(state);
    expect(label).toContain('ClaimedName');
    expect(label).toContain("the app's own claim");
    expect(label).toContain('not verified by OpenKey');
  });

  // F2: the embedded-refusal state is set at initialState() when a message was passed in.
  // That message is driven by the client guard in `+layout.ts` (window.top !== window.self),
  // which fires when framing headers are stripped. Here we assert the state transitions
  // to `embedded-refused` as a hard refusal state.
  test('F2 regression: embedded refusal halts the widget and never accepts a syn', () => {
    const refusalMsg = 'TinyCloud setup cannot run inside an embedded frame.';
    const state = initialState(refusalMsg);
    expect(state.phase).toBe('embedded-refused');
    const afterSyn = applySyn(state, synEvent(APP_ORIGIN));
    expect(afterSyn.phase).toBe('embedded-refused');
    expect(afterSyn.verifiedRequestingOrigin).toBeNull();
  });

  // The ignored opener case: an uninvited window that posts on our page without being the
  // opener can't initiate.
  test('messages from non-opener window are ignored', () => {
    const state = initialState(null);
    const notOpener = {};
    const result = applySyn(state, { origin: APP_ORIGIN, source: notOpener, opener: OPENER, data: { type: 'openkey:tinycloud-setup:request', v: 1 } });
    expect(result.phase).toBe('waiting');
    expect(result.verifiedRequestingOrigin).toBeNull();
  });
});
