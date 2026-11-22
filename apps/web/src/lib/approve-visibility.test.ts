// The tracker behind the framed sign pages' one-passkey cover: the cover counts only after Approve has been reported
// fully in view and not covered for 500 ms without a break, and only while the latest report still says so.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  COVER_VISIBLE_MS,
  coverNotHonoured,
  createApproveVisibility,
  reviewSnapshot,
  sameReview,
  type VisibilityEntryLike,
  type VisibilityObserver,
  type VisibilityObserverFactory,
} from './approve-visibility';
import type { ApprovalPasskeyNeed } from './approval-passkey';

class FakeObserver implements VisibilityObserver {
  targets: Element[] = [];
  disconnects = 0;
  constructor(readonly callback: (entries: readonly VisibilityEntryLike[]) => void) {}
  observe(target: Element) { this.targets.push(target); }
  disconnect() { this.disconnects++; this.targets = []; }
  report(...entries: VisibilityEntryLike[]) { this.callback(entries); }
}

function harness(options: { framed?: boolean; supported?: boolean } = {}) {
  let time = 1_000;
  const observers: FakeObserver[] = [];
  const createObserver: VisibilityObserverFactory = (callback) => {
    if (options.supported === false) return null;
    const observer = new FakeObserver(callback);
    observers.push(observer);
    return observer;
  };
  const tracker = createApproveVisibility({ framed: options.framed ?? true, createObserver, now: () => time });
  const button = {} as Element;
  return {
    tracker,
    observers,
    button,
    advance: (ms: number) => { time += ms; },
    observer: () => observers[0]!,
    view: (visible: boolean) => observers[0]!.report({ isIntersecting: visible, isVisible: visible }),
  };
}

describe('a page that is not framed', () => {
  test('is not gated and builds no observer', () => {
    const h = harness({ framed: false });
    h.tracker.watch(h.button);
    expect(h.observers).toHaveLength(0);
    expect(h.tracker.coverUsable).toBe(true);
    expect(h.tracker.honoursCover()).toBe(true);
  });
});

describe('a framed page without observer v2', () => {
  test('cannot use the cover at all', () => {
    const h = harness({ supported: false });
    expect(h.tracker.coverUsable).toBe(false);
    h.tracker.watch(h.button);
    h.advance(10_000);
    expect(h.tracker.honoursCover()).toBe(false);
  });
});

describe('a framed page with observer v2', () => {
  test('has a usable cover but honours it for nothing before any report', () => {
    const h = harness();
    expect(h.tracker.coverUsable).toBe(true);
    h.tracker.watch(h.button);
    h.advance(10_000);
    expect(h.tracker.honoursCover()).toBe(false);
  });

  test('watches the button it is given and none after null', () => {
    const h = harness();
    h.tracker.watch(h.button);
    expect(h.observer().targets).toEqual([h.button]);
    h.tracker.watch(null);
    expect(h.observer().targets).toEqual([]);
  });

  test('honours the cover at 500 ms in view and not at 499 ms', () => {
    const h = harness();
    h.tracker.watch(h.button);
    h.view(true);
    h.advance(COVER_VISIBLE_MS - 1);
    expect(h.tracker.honoursCover()).toBe(false);
    h.advance(1);
    expect(h.tracker.honoursCover()).toBe(true);
  });

  test('a report of covered or faded resets the window, and the window starts again at the next visible report', () => {
    const h = harness();
    h.tracker.watch(h.button);
    h.view(true);
    h.advance(400);
    h.view(false);
    h.advance(10_000);
    expect(h.tracker.honoursCover()).toBe(false);
    h.view(true);
    h.advance(499);
    expect(h.tracker.honoursCover()).toBe(false);
    h.advance(1);
    expect(h.tracker.honoursCover()).toBe(true);
  });

  test('the latest report decides at the moment of the click, however long Approve was in view before', () => {
    const h = harness();
    h.tracker.watch(h.button);
    h.view(true);
    h.advance(5_000);
    expect(h.tracker.honoursCover()).toBe(true);
    h.view(false);
    expect(h.tracker.honoursCover()).toBe(false);
  });

  test('a report that is fully in view but not visible, or visible but not intersecting, is not in plain view', () => {
    const h = harness();
    h.tracker.watch(h.button);
    h.observer().report({ isIntersecting: true, isVisible: false });
    h.advance(1_000);
    expect(h.tracker.honoursCover()).toBe(false);
    h.observer().report({ isIntersecting: false, isVisible: true });
    h.advance(1_000);
    expect(h.tracker.honoursCover()).toBe(false);
    h.observer().report({ isIntersecting: true });
    h.advance(1_000);
    expect(h.tracker.honoursCover()).toBe(false);
  });

  test('the last entry of a batch is the one that counts', () => {
    const h = harness();
    h.tracker.watch(h.button);
    h.observer().report({ isIntersecting: true, isVisible: false }, { isIntersecting: true, isVisible: true });
    h.advance(COVER_VISIBLE_MS);
    expect(h.tracker.honoursCover()).toBe(true);
    h.observer().report({ isIntersecting: true, isVisible: true }, { isIntersecting: true, isVisible: false });
    expect(h.tracker.honoursCover()).toBe(false);
  });

  test('a repeated visible report does not extend or restart the window', () => {
    const h = harness();
    h.tracker.watch(h.button);
    h.view(true);
    h.advance(300);
    h.view(true);
    h.advance(200);
    expect(h.tracker.honoursCover()).toBe(true);
  });

  test('restart begins the window over while Approve stays in view, and clears it while it is not', () => {
    const h = harness();
    h.tracker.watch(h.button);
    h.view(true);
    h.advance(5_000);
    expect(h.tracker.honoursCover()).toBe(true);
    h.tracker.restart();
    expect(h.tracker.honoursCover()).toBe(false);
    h.advance(COVER_VISIBLE_MS - 1);
    expect(h.tracker.honoursCover()).toBe(false);
    h.advance(1);
    expect(h.tracker.honoursCover()).toBe(true);

    h.view(false);
    h.tracker.restart();
    h.advance(5_000);
    expect(h.tracker.honoursCover()).toBe(false);
    h.view(true);
    h.advance(COVER_VISIBLE_MS);
    expect(h.tracker.honoursCover()).toBe(true);
  });

  test('a new button starts from not seen', () => {
    const h = harness();
    h.tracker.watch(h.button);
    h.view(true);
    h.advance(5_000);
    expect(h.tracker.honoursCover()).toBe(true);
    h.tracker.watch({} as Element);
    expect(h.tracker.honoursCover()).toBe(false);
    h.advance(5_000);
    expect(h.tracker.honoursCover()).toBe(false);
  });
});

describe('which offers the tap holds back', () => {
  const never: ApprovalPasskeyNeed = { required: false };
  const covered: ApprovalPasskeyNeed = { required: false, flowCover: true };
  const asked = { required: true, challengeToken: 'c', options: { challenge: 'x' } } as unknown as ApprovalPasskeyNeed;

  test('only an offer waived by the cover, while the cover is not honoured', () => {
    const h = harness();
    h.tracker.watch(h.button);
    expect(coverNotHonoured(covered, h.tracker)).toBe(true);
    expect(coverNotHonoured(never, h.tracker)).toBe(false);
    expect(coverNotHonoured(asked, h.tracker)).toBe(false);
    expect(coverNotHonoured(null, h.tracker)).toBe(false);
    h.view(true);
    h.advance(COVER_VISIBLE_MS);
    expect(coverNotHonoured(covered, h.tracker)).toBe(false);
  });

  test('never on a page that is not framed', () => {
    const h = harness({ framed: false });
    expect(coverNotHonoured(covered, h.tracker)).toBe(false);
  });
});

describe('whether a refetched offer is for the request that was shown', () => {
  const shown = { input: '["req","key","message",["a"],null,[]]', signedMessage: 'bytes', renewalLeaseMs: null };

  test('the same preview input, bytes and renewal lease continue the tap', () => {
    expect(sameReview(shown, { ...shown })).toBe(true);
  });

  test('a different selection, message, key or chosen expiry in the input does not', () => {
    for (const input of ['["req","key","message",["a","b"],null,[]]', '["req","key","other",["a"],null,[]]',
      '["req","other-key","message",["a"],null,[]]', '["req","key","message",["a"],3600000,[]]']) {
      expect(sameReview(shown, { ...shown, input })).toBe(false);
    }
  });

  test('different sealed bytes do not, even for the same input', () => {
    expect(sameReview(shown, { ...shown, signedMessage: 'other bytes' })).toBe(false);
  });

  test('a different renewal lease does not', () => {
    expect(sameReview({ ...shown, renewalLeaseMs: null }, { ...shown, renewalLeaseMs: 60_000 })).toBe(false);
    expect(sameReview({ ...shown, renewalLeaseMs: 60_000 }, { ...shown, renewalLeaseMs: 60_000 })).toBe(true);
  });

  test('the exact-byte offer continues only for the same key, message and origin', () => {
    const exact = { input: '["key","message","https://cli.tinycloud.xyz"]', signedMessage: '', renewalLeaseMs: null };
    expect(sameReview(exact, { ...exact })).toBe(true);
    expect(sameReview(exact, { ...exact, input: '["key","message changed","https://cli.tinycloud.xyz"]' })).toBe(false);
    expect(sameReview(exact, { ...exact, input: '["key","message","https://other.example"]' })).toBe(false);
  });

  test('no snapshot of what was shown never continues', () => {
    expect(sameReview(null, shown)).toBe(false);
  });

  test('an absent input has no snapshot, so two absent inputs do not match and the tap does not continue', () => {
    for (const absent of [undefined, null, '']) expect(reviewSnapshot(absent, '', null)).toBeNull();
    expect(reviewSnapshot('["key","message",null]', '', null)).toEqual(
      { input: '["key","message",null]', signedMessage: '', renewalLeaseMs: null },
    );
    expect(sameReview(reviewSnapshot(undefined, '', null), reviewSnapshot(undefined, '', null))).toBe(false);
    expect(sameReview(reviewSnapshot(null, '', null), reviewSnapshot('', '', null))).toBe(false);
    expect(sameReview(shown, null)).toBe(false);
    expect(sameReview(null, null)).toBe(false);
  });
});
