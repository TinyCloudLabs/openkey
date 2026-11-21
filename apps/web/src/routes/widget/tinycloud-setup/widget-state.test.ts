// TC-3657 widget-state tests. One case per invariant / regression. The state machine is
// pure; these assertions don't need a Svelte mount harness.
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
  requesterLine,
  startMint,
  visibleErrorForReason,
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
  test('a message from the opener does not mint a ticket (prevents burning the hourly quota before the user taps)', () => {
    const state = initialState(null);
    const afterSyn = applySyn(state, synEvent(APP_ORIGIN));
    expect(afterSyn.verifiedRequestingOrigin).toBe(APP_ORIGIN);
    expect(afterSyn.phase).toBe('review');
    expect(afterSyn.ticket).toBeNull();
    expect(afterSyn.mintInFlight).toBe(false);
  });

  test('a second message from a different origin is ignored (the first capture sticks)', () => {
    const state = initialState(null);
    const first = applySyn(state, synEvent(APP_ORIGIN));
    const attacker = applySyn(first, synEvent('https://attacker.example', { name: 'TakeOver' }));
    expect(attacker.verifiedRequestingOrigin).toBe(APP_ORIGIN);
    expect(attacker.claim).toEqual({});
  });

  test('a rate-limited mint still posts back and keeps the verified origin', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review', mintInFlight: true };
    const { state: next, postBack } = applyMintResult(state, { ok: false, status: 429, body: {}, retryAfterSeconds: 42 });
    expect(next.verifiedRequestingOrigin).toBe(APP_ORIGIN);
    expect(next.replyTargetOrigin).toBe(APP_ORIGIN);
    expect(next.phase).toBe('declined');
    expect(next.mintInFlight).toBe(false);
    expect(next.error).toBe('Too many tries. Try again later.');
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason: 'rate_limited', retryAfter: 42 });
  });

  test('a failed mint posts back a reason envelope and shows the user-facing "setup didn\'t finish" line', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review', mintInFlight: true };
    const { state: next, postBack } = applyMintResult(state, { ok: false, status: 500, body: { error: 'mint_failed' } });
    expect(next.mintInFlight).toBe(false);
    expect(next.error).toBe("Setup didn't finish. Try again.");
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason: 'mint_failed' });
  });

  test('a mint that returns setup_unavailable shows the "setup isn\'t available" line', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review', mintInFlight: true };
    const { state: next } = applyMintResult(state, { ok: false, status: 503, body: { error: 'setup_unavailable' } });
    expect(next.error).toBe("Setup isn't available right now. Try again later.");
  });

  test('a rate-limited publish posts back and keeps the verified origin', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'submitting' };
    const { state: next, postBack } = applyPublishResult(state, { ok: false, status: 429, body: {}, retryAfterSeconds: 7 });
    expect(next.verifiedRequestingOrigin).toBe(APP_ORIGIN);
    expect(next.error).toBe('Too many tries. Try again later.');
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason: 'rate_limited', retryAfter: 7 });
  });

  test('a failed publish shows the "setup didn\'t finish" line and posts back its reason', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'submitting' };
    const { state: next, postBack } = applyPublishResult(state, { ok: false, status: 500, body: { error: 'publish_failed' } });
    expect(next.error).toBe("Setup didn't finish. Try again.");
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'unavailable', reason: 'publish_failed' });
  });

  test('a publish that returns setup_unavailable shows the "setup isn\'t available" line', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'submitting' };
    const { state: next } = applyPublishResult(state, { ok: false, status: 503, body: { error: 'setup_unavailable' } });
    expect(next.error).toBe("Setup isn't available right now. Try again later.");
  });

  test('a successful publish posts back status and subject on the right origin', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'submitting' };
    const { postBack, state: next } = applyPublishResult(state, { ok: true, body: { status: 'published', subject: 'did:pkh:eip155:1:0x1' } });
    expect(next.phase).toBe('done');
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'published', subject: 'did:pkh:eip155:1:0x1' });
  });

  test('a successful mint moves to armed so the button shows its final label', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review', mintInFlight: true };
    const { state: next, postBack } = applyMintResult(state, { ok: true, body: previewBody });
    expect(next.ticket).toBe('t');
    expect(next.preview?.primarySpaceName).toBe('default');
    expect(next.phase).toBe('armed');
    expect(next.mintInFlight).toBe(false);
    expect(postBack).toBeNull();
  });

  test('decline posts back on the verified origin', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review' };
    const { postBack, state: next } = applyDecline(state);
    expect(next.phase).toBe('declined');
    expect(postBack).toEqual({ type: 'openkey:tinycloud-setup:response', v: 1, status: 'declined' });
  });

  test('the approve button at armed names the verified origin (never the caller-asserted name)', () => {
    const state: WidgetState = {
      ...initialState(null),
      verifiedRequestingOrigin: APP_ORIGIN,
      replyTargetOrigin: APP_ORIGIN,
      claim: { name: '<not verified name>' },
      phase: 'armed',
    };
    const label = approveButtonLabel(state);
    expect(label).toBe(`Set up for ${APP_ORIGIN}`);
    expect(label.includes('<not verified name>')).toBe(false);
  });

  test('the approve button at review reads "Preparing…"', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review' };
    expect(approveButtonLabel(state)).toBe('Preparing…');
  });

  test('the approve button at submitting reads "Setting up…"', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'submitting' };
    expect(approveButtonLabel(state)).toBe('Setting up…');
  });

  test('the claim line labels the name as the app\'s own claim', () => {
    const state: WidgetState = {
      ...initialState(null),
      verifiedRequestingOrigin: APP_ORIGIN,
      replyTargetOrigin: APP_ORIGIN,
      claim: { name: 'ClaimedName' },
      phase: 'armed',
    };
    const label = claimLabel(state);
    expect(label).toContain('ClaimedName');
    expect(label).toContain("OpenKey hasn't checked");
  });

  test('the requester line names the browser-verified origin', () => {
    const state: WidgetState = {
      ...initialState(null),
      verifiedRequestingOrigin: APP_ORIGIN,
      replyTargetOrigin: APP_ORIGIN,
      phase: 'armed',
    };
    const line = requesterLine(state);
    expect(line).toBe(`${APP_ORIGIN} asked to set up your TinyCloud.`);
  });

  test('the requester line is null when the origin has not been captured', () => {
    const state = initialState(null);
    expect(requesterLine(state)).toBeNull();
  });

  test('the embedded-refusal state halts the widget and never accepts a message', () => {
    const refusalMsg = 'Setup has to open in its own window. Go back to the app, allow pop-ups and try again.';
    const state = initialState(refusalMsg);
    expect(state.phase).toBe('embedded-refused');
    const afterSyn = applySyn(state, synEvent(APP_ORIGIN));
    expect(afterSyn.phase).toBe('embedded-refused');
    expect(afterSyn.verifiedRequestingOrigin).toBeNull();
  });

  test('messages from a non-opener window are ignored', () => {
    const state = initialState(null);
    const notOpener = {};
    const result = applySyn(state, { origin: APP_ORIGIN, source: notOpener, opener: OPENER, data: { type: 'openkey:tinycloud-setup:request', v: 1 } });
    expect(result.phase).toBe('waiting');
    expect(result.verifiedRequestingOrigin).toBeNull();
  });

  test('startMint sets mintInFlight; both success and failure clear it', () => {
    const state: WidgetState = { ...initialState(null), verifiedRequestingOrigin: APP_ORIGIN, replyTargetOrigin: APP_ORIGIN, phase: 'review' };
    const flagged = startMint(state);
    expect(flagged.mintInFlight).toBe(true);
    const { state: success } = applyMintResult(flagged, { ok: true, body: previewBody });
    expect(success.mintInFlight).toBe(false);
    const { state: failure } = applyMintResult(flagged, { ok: false, status: 500, body: {} });
    expect(failure.mintInFlight).toBe(false);
  });

  test('visibleErrorForReason maps setup_unavailable and everything else to the two user-facing lines', () => {
    expect(visibleErrorForReason('setup_unavailable')).toBe("Setup isn't available right now. Try again later.");
    expect(visibleErrorForReason('mint_failed')).toBe("Setup didn't finish. Try again.");
    expect(visibleErrorForReason('publish_failed')).toBe("Setup didn't finish. Try again.");
    expect(visibleErrorForReason(undefined)).toBe("Setup didn't finish. Try again.");
  });
});
