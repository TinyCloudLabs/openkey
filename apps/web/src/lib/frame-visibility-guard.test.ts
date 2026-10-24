// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, afterEach, beforeEach, describe, expect, test, vi } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import {
  VISIBILITY_ENABLE_DELAY_MS,
  createVisibilityGuard,
  isEntryVisible,
  isFramed,
  targetState,
  watchFrameVisibility,
  type VisibilityEntry,
} from './frame-visibility-guard';

// No files are touched. HOME is pointed at a private dir (and put back); the
// cleanup is registered first. Time is driven with fake timers.
const PRIOR_HOME = process.env.HOME;
const HOME = mkdtempSync(join('/var/tmp', 'tc1950.'));
afterAll(() => {
  if (PRIOR_HOME === undefined) delete process.env.HOME;
  else process.env.HOME = PRIOR_HOME;
  rmSync(HOME, { recursive: true, force: true });
});
process.env.HOME = HOME;

// Test stand-ins for browser globals; the real ones are put back after each test.
const fakeGlobals = globalThis as unknown as Record<string, unknown>;

const VIEWPORT = { width: 520, height: 780 };
const rect = (width: number, height: number) => ({ width, height });
// The whole view, fully in the frame, visible.
const FULL: VisibilityEntry = {
  isIntersecting: true,
  intersectionRatio: 1,
  isVisible: true,
  intersectionRect: rect(520, 600),
  boundingClientRect: rect(520, 600),
};
const COVERED: VisibilityEntry = { ...FULL, isVisible: false };

afterEach(() => {
  vi.useRealTimers();
});

describe('isEntryVisible', () => {
  test('home is the private dir', () => {
    expect(process.env.HOME).toBe(HOME);
  });

  test('with v2 an element that still intersects but is covered is not visible', () => {
    expect(isEntryVisible({ isIntersecting: true, intersectionRatio: 1, isVisible: false }, true)).toBe(false);
    expect(isEntryVisible({ isIntersecting: true, intersectionRatio: 1, isVisible: true }, true)).toBe(true);
  });

  test('with v2 an entry without `isVisible` is not visible', () => {
    expect(isEntryVisible({ isIntersecting: true, intersectionRatio: 1 }, true)).toBe(false);
  });

  test('without v2 `isVisible` is not needed, but cropping and scrolling away still count', () => {
    expect(isEntryVisible({ isIntersecting: true, intersectionRatio: 1 }, false)).toBe(true);
    expect(isEntryVisible({ isIntersecting: true, intersectionRatio: 0.5 }, false)).toBe(false);
    expect(isEntryVisible({ isIntersecting: false, intersectionRatio: 0 }, false)).toBe(false);
  });

  test('the required ratio can be lowered for a tall element', () => {
    expect(isEntryVisible({ isIntersecting: true, intersectionRatio: 0.6 }, false, 0.5)).toBe(true);
    expect(isEntryVisible({ isIntersecting: true, intersectionRatio: 0.4 }, false, 0.5)).toBe(false);
  });
});

describe('targetState', () => {
  const frame = { width: 300, height: 680 };

  test('a view that fills the frame is visible', () => {
    expect(targetState(FULL, true, VIEWPORT)).toBe('visible');
  });

  test('a view taller than the frame is judged by the part that fits', () => {
    const tall = { ...FULL, boundingClientRect: rect(520, 1400), intersectionRect: rect(520, 780) };
    expect(targetState(tall, true, VIEWPORT)).toBe('visible');
  });

  test('a view that starts part-way down the frame is judged by the part inside the frame', () => {
    const offset = { ...FULL, boundingClientRect: { width: 226, height: 1207, top: 141, left: 0 }, intersectionRect: rect(226, 539) };
    expect(targetState(offset, true, frame)).toBe('visible');
    expect(targetState({ ...offset, intersectionRect: rect(226, 300) }, true, frame)).toBe('obscured');
    expect(targetState({ ...offset, isVisible: false }, true, frame)).toBe('obscured');
  });

  test('a covered view is obscured although it intersects', () => {
    expect(targetState(COVERED, true, VIEWPORT)).toBe('obscured');
  });

  test('a view cropped by the embedding page is obscured, vertically and horizontally', () => {
    expect(targetState({ ...FULL, intersectionRect: rect(520, 300) }, true, VIEWPORT)).toBe('obscured');
    expect(targetState({ ...FULL, intersectionRect: rect(200, 600) }, true, VIEWPORT)).toBe('obscured');
  });

  test('a frame that is itself off screen in the embedding page is obscured', () => {
    const offscreen = { ...FULL, isIntersecting: false, intersectionRatio: 0, intersectionRect: rect(0, 0) };
    expect(targetState(offscreen, true, VIEWPORT)).toBe('obscured');
  });

  test('a target scrolled out of the frame is out, not obscured', () => {
    const below = { ...FULL, isIntersecting: false, intersectionRatio: 0, boundingClientRect: { width: 520, height: 108, top: 900, left: 0 }, intersectionRect: rect(0, 0) };
    const above = { ...below, boundingClientRect: { width: 520, height: 108, top: -300, left: 0 } };
    expect(targetState(below, true, VIEWPORT)).toBe('out');
    expect(targetState(above, true, VIEWPORT)).toBe('out');
  });

  test('an entry without geometry is obscured', () => {
    expect(targetState({ isIntersecting: true, intersectionRatio: 1, isVisible: true }, true, VIEWPORT)).toBe('obscured');
  });

  test('without v2 a covered view cannot be seen, cropping can', () => {
    const noV2 = { ...FULL, isVisible: undefined };
    expect(targetState(noV2, false, VIEWPORT)).toBe('visible');
    expect(targetState({ ...noV2, intersectionRect: rect(520, 300) }, false, VIEWPORT)).toBe('obscured');
  });
});

describe('createVisibilityGuard', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  function make() {
    const changes: boolean[] = [];
    const guard = createVisibilityGuard({ targets: ['view', 'actions'], onChange: (allowed) => changes.push(allowed) });
    return { guard, changes };
  }

  test('is closed until every target has been visible for the whole delay', () => {
    const { guard, changes } = make();
    expect(guard.allowed).toBe(false);
    guard.report('view', true);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 2);
    expect(guard.allowed).toBe(false);
    guard.report('actions', true);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS - 1);
    expect(guard.allowed).toBe(false);
    vi.advanceTimersByTime(1);
    expect(guard.allowed).toBe(true);
    expect(changes).toEqual([true]);
  });

  test('losing visibility closes at once and the delay starts over', () => {
    const { guard, changes } = make();
    guard.report('view', true);
    guard.report('actions', true);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(guard.allowed).toBe(true);
    guard.report('view', false);
    expect(guard.allowed).toBe(false);
    guard.report('view', true);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS - 1);
    expect(guard.allowed).toBe(false);
    vi.advanceTimersByTime(1);
    expect(guard.allowed).toBe(true);
    expect(changes).toEqual([true, false, true]);
  });

  test('a flicker inside the delay does not shorten it', () => {
    const { guard } = make();
    guard.report('view', true);
    guard.report('actions', true);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS - 100);
    guard.report('view', false);
    guard.report('view', true);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS - 1);
    expect(guard.allowed).toBe(false);
    vi.advanceTimersByTime(1);
    expect(guard.allowed).toBe(true);
  });

  test('a hidden page closes it and a rearm starts the delay over', () => {
    const { guard } = make();
    guard.report('view', true);
    guard.report('actions', true);
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

  test('stop cancels a pending delay', () => {
    const { guard } = make();
    guard.report('view', true);
    guard.report('actions', true);
    guard.stop();
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 2);
    expect(guard.allowed).toBe(false);
  });
});

// A browser stand-in: an observer whose records the test controls, a window
// and a document with listeners, and a settable visibility state.
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
  const realGlobals = {
    IntersectionObserver: fakeGlobals.IntersectionObserver,
    window: fakeGlobals.window,
    document: fakeGlobals.document,
  };
  let windowListeners: Record<string, Array<() => void>>;
  let documentListeners: Record<string, Array<() => void>>;
  let doc: { visibilityState: string };
  let frameWindow: { innerWidth: number; innerHeight: number };
  const element = (name: string) => ({ name }) as unknown as Element;
  const view = element('view');
  const actions = element('actions');
  const entry = (target: Element, state: VisibilityEntry) => ({ target, ...state }) as unknown as IntersectionObserverEntry;
  const viewEntry = (state: VisibilityEntry = FULL) => entry(view, state);
  // The action row sits at the bottom of the view; `top` is its place in the frame.
  const actionsEntry = (state: VisibilityEntry = FULL, top = 400) =>
    entry(actions, { ...state, boundingClientRect: { width: 520, height: 108, top, left: 0 }, intersectionRect: state.intersectionRect ? rect(520, state.isIntersecting ? 108 : 0) : undefined });

  beforeEach(() => {
    vi.useFakeTimers();
    FakeObserver.instances = [];
    windowListeners = {};
    documentListeners = {};
    doc = { visibilityState: 'visible' };
    frameWindow = { innerWidth: 520, innerHeight: 780 };
    fakeGlobals.IntersectionObserver = FakeObserver;
    fakeGlobals.window = {
      get innerWidth() {
        return frameWindow.innerWidth;
      },
      get innerHeight() {
        return frameWindow.innerHeight;
      },
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
    for (const [name, value] of Object.entries(realGlobals)) {
      if (value === undefined) Reflect.deleteProperty(globalThis, name);
      else fakeGlobals[name] = value;
    }
  });

  function start() {
    const changes: boolean[] = [];
    const binding = watchFrameVisibility({ view, actions }, (allowed) => changes.push(allowed));
    const observer = FakeObserver.instances[0]!;
    return { binding, observer, changes };
  }

  function showAll(observer: FakeObserver, state: VisibilityEntry = FULL) {
    observer.callback([viewEntry(state), actionsEntry(state)]);
  }

  test('asks the browser to track visibility and observes the view and the action row', () => {
    const { observer } = start();
    expect(observer.options.trackVisibility).toBe(true);
    expect(observer.options.delay).toBeGreaterThanOrEqual(100);
    expect(observer.observed).toEqual([view, actions]);
  });

  test('a covered view stays closed: intersecting but `isVisible` false', () => {
    const { binding, observer } = start();
    showAll(observer, COVERED);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 10);
    expect(binding.allowed).toBe(false);
    expect(binding.confirmNow()).toBe(false);
  });

  test('a view cropped by the embedding page stays closed', () => {
    const { binding, observer } = start();
    showAll(observer, { ...FULL, intersectionRect: rect(520, 300) });
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 10);
    expect(binding.allowed).toBe(false);
  });

  test('opens after the delay when the view and the action row are in view', () => {
    const { binding, observer, changes } = start();
    showAll(observer);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);
    expect(changes).toEqual([true]);
  });

  test('a covered action row closes it although the view itself is visible', () => {
    const { binding, observer } = start();
    showAll(observer);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);
    observer.callback([actionsEntry(COVERED)]);
    expect(binding.allowed).toBe(false);
  });

  test('a short frame: the action row below the fold is out of view and does not block', () => {
    frameWindow.innerHeight = 300;
    const { binding, observer } = start();
    observer.callback([
      viewEntry({ ...FULL, boundingClientRect: { width: 520, height: 600, top: 141, left: 0 }, intersectionRect: rect(520, 159) }),
      actionsEntry({ ...FULL, isIntersecting: false, intersectionRatio: 0, isVisible: false, intersectionRect: rect(0, 0) }, 520),
    ]);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);
  });

  test('a short frame whose visible part is covered stays closed', () => {
    frameWindow.innerHeight = 300;
    const { binding, observer } = start();
    observer.callback([
      viewEntry({ ...COVERED, boundingClientRect: { width: 520, height: 600, top: 141, left: 0 }, intersectionRect: rect(520, 159) }),
      actionsEntry({ ...FULL, isIntersecting: false, intersectionRatio: 0, isVisible: false, intersectionRect: rect(0, 0) }, 520),
    ]);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 5);
    expect(binding.allowed).toBe(false);
  });

  test('nothing is allowed before both targets have reported', () => {
    const { binding, observer } = start();
    observer.callback([viewEntry()]);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 5);
    expect(binding.allowed).toBe(false);
    observer.callback([actionsEntry()]);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);
  });

  test('window blur and a hidden tab each close it and start the delay over', () => {
    const { binding, observer } = start();
    showAll(observer);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);

    windowListeners.blur!.forEach((fn) => fn());
    expect(binding.allowed).toBe(false);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS - 1);
    expect(binding.allowed).toBe(false);
    vi.advanceTimersByTime(1);
    expect(binding.allowed).toBe(true);

    doc.visibilityState = 'hidden';
    documentListeners.visibilitychange!.forEach((fn) => fn());
    expect(binding.allowed).toBe(false);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS * 5);
    expect(binding.allowed).toBe(false);
    doc.visibilityState = 'visible';
    documentListeners.visibilitychange!.forEach((fn) => fn());
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS - 1);
    expect(binding.allowed).toBe(false);
    vi.advanceTimersByTime(1);
    expect(binding.allowed).toBe(true);
  });

  test('a frame that was never focused still opens, and gaining focus does not close it', () => {
    const { binding, observer } = start();
    showAll(observer);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);
    expect(windowListeners.focus ?? []).toEqual([]);
  });

  test('confirmNow reads pending records: a click right after a cover is refused', () => {
    const { binding, observer } = start();
    showAll(observer);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);
    observer.pending = [viewEntry(COVERED)];
    expect(binding.confirmNow()).toBe(false);
    expect(binding.allowed).toBe(false);
  });

  test('confirmNow with nothing pending keeps an open guard open', () => {
    const { binding, observer } = start();
    showAll(observer);
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.confirmNow()).toBe(true);
  });

  test('without v2 the observer property is false and `isVisible` is not needed', () => {
    const noV2 = class extends FakeObserver {
      override trackVisibility = false;
    };
    fakeGlobals.IntersectionObserver = noV2;
    const { binding, observer } = start();
    showAll(observer, { ...FULL, isVisible: undefined });
    vi.advanceTimersByTime(VISIBILITY_ENABLE_DELAY_MS);
    expect(binding.allowed).toBe(true);
  });

  test('stop removes the listeners and disconnects', () => {
    const { binding, observer } = start();
    binding.stop();
    expect(observer.disconnected).toBe(true);
    expect(windowListeners.blur).toEqual([]);
    expect(documentListeners.visibilitychange).toEqual([]);
  });
});

describe('isFramed', () => {
  const realWindow = fakeGlobals.window;
  afterEach(() => {
    if (realWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
    else fakeGlobals.window = realWindow;
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
