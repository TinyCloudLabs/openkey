import { afterAll, afterEach, beforeEach, describe, expect, test, vi } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import {
  VISIBILITY_ENABLE_DELAY_MS,
  createVisibilityGuard,
  isFramed,
  watchFrameVisibility,
  type VisibilityEntry,
} from '../../../web/src/lib/frame-visibility-guard';

// No files are touched. HOME is pointed at a private dir (and put back); the
// cleanup is registered first. Time is driven with fake timers.
const PRIOR_HOME = process.env.HOME;
const HOME = mkdtempSync(join('/var/tmp', 'tc1950.'));
afterAll(() => {
  process.env.HOME = PRIOR_HOME;
  rmSync(HOME, { recursive: true, force: true });
});
process.env.HOME = HOME;

// Test stand-ins for browser globals; the real ones are put back after each test.
const fakeGlobals = globalThis as unknown as Record<string, unknown>;

const FULL: VisibilityEntry = { isIntersecting: true, intersectionRatio: 1, isVisible: true };
const COVERED: VisibilityEntry = { isIntersecting: true, intersectionRatio: 1, isVisible: false };
const CROPPED: VisibilityEntry = { isIntersecting: true, intersectionRatio: 0.5, isVisible: true };
const OFFSCREEN: VisibilityEntry = { isIntersecting: false, intersectionRatio: 0, isVisible: false };

afterEach(() => {
  vi.useRealTimers();
});

describe('createVisibilityGuard', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  function make(trackVisibility = true) {
    const changes: boolean[] = [];
    const guard = createVisibilityGuard({ targets: ['summary', 'button'], trackVisibility, onChange: (allowed) => changes.push(allowed) });
    return { guard, changes };
  }

  test('home is the private dir', () => {
    expect(process.env.HOME).toBe(HOME);
  });

  test('is closed until every target has been fully visible for the whole delay', () => {
    const { guard, changes } = make();
    expect(guard.allowed).toBe(false);
    guard.report('summary', FULL);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 2);
    expect(guard.allowed).toBe(false);
    guard.report('button', FULL);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS - 1);
    expect(guard.allowed).toBe(false);
    vi.advanceTimersByTime(1);
    expect(guard.allowed).toBe(true);
    expect(changes).toEqual([true]);
  });

  test('a covered element stays closed even though it still intersects', () => {
    const { guard } = make(true);
    guard.report('summary', FULL);
    guard.report('button', COVERED);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 10);
    expect(guard.allowed).toBe(false);
  });

  test('a cropped or scrolled-away element stays closed', () => {
    for (const hidden of [CROPPED, OFFSCREEN]) {
      const { guard } = make();
      guard.report('summary', FULL);
      guard.report('button', hidden);
      vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 10);
      expect(guard.allowed).toBe(false);
    }
  });

  test('losing visibility closes at once and the delay starts over', () => {
    const { guard, changes } = make();
    guard.report('summary', FULL);
    guard.report('button', FULL);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(guard.allowed).toBe(true);
    guard.report('button', COVERED);
    expect(guard.allowed).toBe(false);
    guard.report('button', FULL);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS - 1);
    expect(guard.allowed).toBe(false);
    vi.advanceTimersByTime(1);
    expect(guard.allowed).toBe(true);
    expect(changes).toEqual([true, false, true]);
  });

  test('a flicker inside the delay does not shorten it', () => {
    const { guard } = make();
    guard.report('summary', FULL);
    guard.report('button', FULL);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS - 100);
    guard.report('button', COVERED);
    guard.report('button', FULL);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS - 1);
    expect(guard.allowed).toBe(false);
    vi.advanceTimersByTime(1);
    expect(guard.allowed).toBe(true);
  });

  test('a hidden page closes it and a rearm starts the delay over', () => {
    const { guard } = make();
    guard.report('summary', FULL);
    guard.report('button', FULL);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    guard.setPageVisible(false);
    expect(guard.allowed).toBe(false);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 5);
    expect(guard.allowed).toBe(false);
    guard.setPageVisible(true);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(guard.allowed).toBe(true);
    guard.rearm();
    expect(guard.allowed).toBe(false);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(guard.allowed).toBe(true);
  });

  test('without IntersectionObserver v2 cropping is caught but `isVisible` is not required', () => {
    const noV2: VisibilityEntry = { isIntersecting: true, intersectionRatio: 1 };
    const { guard } = make(false);
    guard.report('summary', noV2);
    guard.report('button', noV2);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(guard.allowed).toBe(true);
    guard.report('button', { isIntersecting: true, intersectionRatio: 0.5 });
    expect(guard.allowed).toBe(false);
  });

  test('with v2 an entry that has no `isVisible` is not visible', () => {
    const { guard } = make(true);
    guard.report('summary', { isIntersecting: true, intersectionRatio: 1 });
    guard.report('button', { isIntersecting: true, intersectionRatio: 1 });
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 5);
    expect(guard.allowed).toBe(false);
  });

  test('stop cancels a pending delay', () => {
    const { guard } = make();
    guard.report('summary', FULL);
    guard.report('button', FULL);
    guard.stop();
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 2);
    expect(guard.allowed).toBe(false);
  });
});

// A browser stand-in: an observer whose records the test controls, a window
// and a document with listeners, and a settable focus/visibility state.
class FakeObserver {
  static instances: FakeObserver[] = [];
  trackVisibility = true;
  observed: Element[] = [];
  pending: IntersectionObserverEntry[] = [];
  disconnected = false;
  constructor(public callback: (entries: IntersectionObserverEntry[]) => void, public options: Record<string, unknown>) {
    FakeObserver.instances.push(this);
  }
  observe(element: Element) {
    this.observed.push(element);
  }
  disconnect() {
    this.disconnected = true;
  }
  takeRecords() {
    const taken = this.pending;
    this.pending = [];
    return taken;
  }
}

describe('watchFrameVisibility', () => {
  const realGlobals = { IntersectionObserver: fakeGlobals.IntersectionObserver, window: fakeGlobals.window, document: fakeGlobals.document };
  let windowListeners: Record<string, Array<() => void>>;
  let documentListeners: Record<string, Array<() => void>>;
  let doc: { visibilityState: string; hasFocus: () => boolean };
  const summary = { name: 'summary-element' } as unknown as Element;
  const button = { name: 'button-element' } as unknown as Element;
  const entry = (target: Element, state: VisibilityEntry) => ({ target, ...state }) as unknown as IntersectionObserverEntry;

  beforeEach(() => {
    vi.useFakeTimers();
    FakeObserver.instances = [];
    windowListeners = {};
    documentListeners = {};
    doc = { visibilityState: 'visible', hasFocus: () => true };
    fakeGlobals.IntersectionObserver = FakeObserver;
    fakeGlobals.window = {
      addEventListener: (type: string, fn: () => void) => (windowListeners[type] ??= []).push(fn),
      removeEventListener: (type: string, fn: () => void) => {
        windowListeners[type] = (windowListeners[type] ?? []).filter((listener) => listener !== fn);
      },
    };
    fakeGlobals.document = Object.assign(doc, {
      addEventListener: (type: string, fn: () => void) => (documentListeners[type] ??= []).push(fn),
      removeEventListener: (type: string, fn: () => void) => {
        documentListeners[type] = (documentListeners[type] ?? []).filter((listener) => listener !== fn);
      },
    });
  });

  afterEach(() => {
    Object.assign(globalThis, realGlobals);
  });

  function start() {
    const changes: boolean[] = [];
    const binding = watchFrameVisibility(
      [{ name: 'summary', element: summary }, { name: 'button', element: button }],
      (allowed) => changes.push(allowed),
    );
    const observer = FakeObserver.instances[0]!;
    return { binding, observer, changes };
  }

  function showBoth(observer: FakeObserver, state: VisibilityEntry = FULL) {
    observer.callback([entry(summary, state), entry(button, state)]);
  }

  test('asks the browser to track visibility and observes both parts', () => {
    const { observer } = start();
    expect(observer.options.trackVisibility).toBe(true);
    expect(observer.options.delay).toBeGreaterThanOrEqual(100);
    expect(observer.observed).toEqual([summary, button]);
  });

  test('a covered view stays closed: intersecting but `isVisible` false', () => {
    const { binding, observer } = start();
    showBoth(observer, COVERED);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 10);
    expect(binding.allowed).toBe(false);
    expect(binding.confirmNow()).toBe(false);
  });

  test('opens after the delay when both parts are fully visible', () => {
    const { binding, observer, changes } = start();
    showBoth(observer);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);
    expect(changes).toEqual([true]);
  });

  test('window blur and a hidden tab each close it and start the delay over', () => {
    const { binding, observer } = start();
    showBoth(observer);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);

    doc.hasFocus = () => false;
    windowListeners.blur!.forEach((fn) => fn());
    expect(binding.allowed).toBe(false);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 5);
    expect(binding.allowed).toBe(false);

    doc.hasFocus = () => true;
    windowListeners.focus!.forEach((fn) => fn());
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS - 1);
    expect(binding.allowed).toBe(false);
    vi.advanceTimersByTime(1);
    expect(binding.allowed).toBe(true);

    doc.visibilityState = 'hidden';
    documentListeners.visibilitychange!.forEach((fn) => fn());
    expect(binding.allowed).toBe(false);
    doc.visibilityState = 'visible';
    documentListeners.visibilitychange!.forEach((fn) => fn());
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);
  });

  test('a page that starts unfocused stays closed until focus', () => {
    doc.hasFocus = () => false;
    const { binding, observer } = start();
    showBoth(observer);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 5);
    expect(binding.allowed).toBe(false);
  });

  test('confirmNow reads pending records: a click right after a cover is refused', () => {
    const { binding, observer } = start();
    showBoth(observer);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);
    observer.pending = [entry(button, COVERED)];
    expect(binding.confirmNow()).toBe(false);
    expect(binding.allowed).toBe(false);
  });

  test('confirmNow with nothing pending keeps an open guard open', () => {
    const { binding, observer } = start();
    showBoth(observer);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.confirmNow()).toBe(true);
  });

  test('without v2 the observer property is false and `isVisible` is not needed', () => {
    const noV2 = class extends FakeObserver {
      override trackVisibility = false;
    };
    fakeGlobals.IntersectionObserver = noV2;
    const { binding, observer } = start();
    showBoth(observer, { isIntersecting: true, intersectionRatio: 1 });
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);
  });

  test('stop removes the listeners and disconnects', () => {
    const { binding, observer } = start();
    binding.stop();
    expect(observer.disconnected).toBe(true);
    expect(windowListeners.blur).toEqual([]);
    expect(windowListeners.focus).toEqual([]);
    expect(documentListeners.visibilitychange).toEqual([]);
  });
});

describe('isFramed', () => {
  const realWindow = fakeGlobals.window;
  afterEach(() => {
    fakeGlobals.window = realWindow;
  });

  test('top-level is not framed, a different top or an unreadable top is', () => {
    const top = {};
    fakeGlobals.window = { self: top, top };
    expect(isFramed()).toBe(false);
    fakeGlobals.window = { self: {}, top };
    expect(isFramed()).toBe(true);
    fakeGlobals.window = {
      self: {},
      get top() {
        throw new Error('cross-origin');
      },
    };
    expect(isFramed()).toBe(true);
  });
});
