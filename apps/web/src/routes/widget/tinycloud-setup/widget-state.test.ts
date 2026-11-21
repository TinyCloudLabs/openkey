// TC-3657 Bobbie 15:16:27Z + 15:42:43Z widget-state tests. One test per regression /
// clarification. The state machine is pure; these assertions don't need a Svelte mount
// harness.
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
  startMint,
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
    expect(afterSyn.mintInFlight).toBe(false);
  });

  // F7 strengthens into: a second syn from a different origin cannot overwrite the first.
  test('F7 regression: a second syn from a different origin is ignored', () => {
    const state = initialState(null);
    const first = applySyn(state, synEvent(APP_ORIGIN));
    const attacker = applySyn(first, synEvent('https://attacker.example', { name: 'TakeOver' }));
    expect(attacker.verifiedRequestingOrigin).toBe(APP_ORIGIN);
    expect(attacker.claim).toEqual({});
  });

  // F4: every post-back path carries the verified origin.
  test('F4 regression: 429 mint still posts back; state keeps verifiedRequestingOrigin', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review', mintInFlight: true };
    const { state: next, postBack } = applyMintResult(state, { ok: false, status: 429, body: {}, retryAfterSeconds: 42 });
    expect(next.verifiedRequestingOrigin).toBe(APP_ORIGIN);
    expect(next.replyTargetOrigin).toBe(APP_ORIGIN);
    expect(next.phase).toBe('declined');
    expect(next.mintInFlight).toBe(false);
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason: 'rate_limited', retryAfter: 42 });
  });

  test('F4 regression: failed mint still posts back a reason envelope', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review', mintInFlight: true };
    const { state: next, postBack } = applyMintResult(state, { ok: false, status: 500, body: { error: 'mint_failed' } });
    expect(next.mintInFlight).toBe(false);
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

  // N4: successful mint transitions directly to `armed` so `approveButtonLabel` can show
  // the verified origin. The Svelte component layers the F1 arm-delay on top by keeping
  // the button disabled for ARM_DELAY_MS.
  test('N4 regression: successful mint transitions to phase=armed; label reads "Approve for <origin>"', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review', mintInFlight: true };
    const { state: next, postBack } = applyMintResult(state, { ok: true, body: previewBody });
    expect(next.ticket).toBe('t');
    expect(next.preview?.primarySpaceName).toBe('default');
    expect(next.phase).toBe('armed');
    expect(next.mintInFlight).toBe(false);
    expect(postBack).toBeNull();
    expect(approveButtonLabel(next)).toBe(`Approve for ${APP_ORIGIN}`);
  });

  test('F4 regression: decline posts back on the verified origin', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review' };
    const { postBack, state: next } = applyDecline(state);
    expect(next.phase).toBe('declined');
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'declined' });
  });

  // F8: the Approve button label uses the verified origin, not the caller-asserted name.
  test('F8 regression: approve button label in phase=armed uses the verified origin, never the claimed app name', () => {
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

  // F2: embedded refusal is a hard refusal state.
  test('F2 regression: embedded refusal halts the widget and never accepts a syn', () => {
    const refusalMsg = 'TinyCloud setup cannot run inside an embedded frame.';
    const state = initialState(refusalMsg);
    expect(state.phase).toBe('embedded-refused');
    const afterSyn = applySyn(state, synEvent(APP_ORIGIN));
    expect(afterSyn.phase).toBe('embedded-refused');
    expect(afterSyn.verifiedRequestingOrigin).toBeNull();
  });

  test('messages from non-opener window are ignored', () => {
    const state = initialState(null);
    const notOpener = {};
    const result = applySyn(state, { origin: APP_ORIGIN, source: notOpener, opener: OPENER, data: { type: 'openkey:tinycloud-setup:request', v: 1 } });
    expect(result.phase).toBe('waiting');
    expect(result.verifiedRequestingOrigin).toBeNull();
  });

  // N6: in-flight guard. `startMint` sets the flag; `applyMintResult` clears it. The
  // Svelte click handler consults `state.mintInFlight` before starting a second mint.
  test('N6 regression: startMint sets mintInFlight; mint result clears it', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review' };
    const flagged = startMint(state);
    expect(flagged.mintInFlight).toBe(true);
    const { state: success } = applyMintResult(flagged, { ok: true, body: previewBody });
    expect(success.mintInFlight).toBe(false);
    const { state: failure } = applyMintResult(flagged, { ok: false, status: 500, body: {} });
    expect(failure.mintInFlight).toBe(false);
  });
});
