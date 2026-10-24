// Visibility guard for the approval view while it is shown inside a frame.
//
// Approve is available only after the view has stayed fully visible and
// uncovered for a continuous delay, with the page visible. Any loss of
// visibility, window blur or tab hide starts the delay again. A click is
// accepted only if the newest visibility reports still say visible.
//
// Two parts of the view are watched: the whole view (the dialog) and its
// action row. Each is `visible` (inside the frame and unobscured), `obscured`
// (inside the frame but covered, faded, transformed or cropped by the
// embedding page) or `out` (entirely outside the frame's own viewport, for
// example scrolled away; it cannot be clicked until it is scrolled into view).
// Only `obscured` blocks. Where the browser supports IntersectionObserver v2
// (`trackVisibility`), `entry.isVisible` is what turns false when a target is
// covered; `isIntersecting` stays true in that case. Without v2 only cropping
// and scrolling away are detected.

export const VISIBILITY_ENABLE_DELAY_MS = 600;
export const VISIBILITY_TRACKING_DELAY_MS = 100;
export const MIN_VISIBLE_RATIO = 0.99;

interface Size {
  width: number;
  height: number;
}

/** A box in the target's own viewport; `top` and `left` default to 0. */
interface Box extends Size {
  top?: number;
  left?: number;
}

/** The fields of an `IntersectionObserverEntry` the guard reads. */
export interface VisibilityEntry {
  isIntersecting: boolean;
  intersectionRatio: number;
  /** Present only where the browser supports IntersectionObserver v2. */
  isVisible?: boolean;
  intersectionRect?: Box;
  boundingClientRect?: Box;
}

export interface VisibilityGuard {
  /** True once every target has stayed visible for the enable delay. */
  readonly allowed: boolean;
  report(target: string, visible: boolean): void;
  /** The page became visible or hidden. */
  setPageVisible(visible: boolean): void;
  /** Start the delay again from now. */
  rearm(): void;
  stop(): void;
}

export interface VisibilityGuardOptions {
  targets: readonly string[];
  onChange: (allowed: boolean) => void;
  enableDelayMs?: number;
}

/**
 * A target counts as visible when it intersects at least `minRatio` of itself
 * and, with IntersectionObserver v2, the browser reports it visible (not
 * covered, faded or transformed).
 */
export function isEntryVisible(entry: VisibilityEntry, trackVisibility: boolean, minRatio = MIN_VISIBLE_RATIO): boolean {
  if (!entry.isIntersecting || entry.intersectionRatio < minRatio) return false;
  return !trackVisibility || entry.isVisible === true;
}

export type TargetState = "visible" | "obscured" | "out";

/**
 * Where a watched target stands. The part of it that lies inside the frame's
 * own viewport must be all in view: nothing outside the frame (the embedding
 * page) clips it and, with IntersectionObserver v2, nothing covers it. A
 * target taller than the frame, or one that starts part-way down it, is judged
 * by the part that fits. A target with no part inside the frame is `out`.
 */
export function targetState(entry: VisibilityEntry, trackVisibility: boolean, viewport: Size): TargetState {
  const seen = entry.intersectionRect;
  const whole = entry.boundingClientRect;
  if (!seen || !whole) return "obscured";
  const left = whole.left ?? 0;
  const top = whole.top ?? 0;
  const inFrameWidth = Math.min(left + whole.width, viewport.width) - Math.max(left, 0);
  const inFrameHeight = Math.min(top + whole.height, viewport.height) - Math.max(top, 0);
  if (inFrameWidth <= 0 || inFrameHeight <= 0) return "out";
  if (!isEntryVisible(entry, trackVisibility, 0)) return "obscured";
  const covers = seen.width >= inFrameWidth * MIN_VISIBLE_RATIO && seen.height >= inFrameHeight * MIN_VISIBLE_RATIO;
  return covers ? "visible" : "obscured";
}

export function createVisibilityGuard(options: VisibilityGuardOptions): VisibilityGuard {
  const { targets, onChange } = options;
  const delay = options.enableDelayMs ?? VISIBILITY_ENABLE_DELAY_MS;
  const visible: Record<string, boolean> = {};
  let pageVisible = true;
  let allowed = false;
  let armed = false;
  let cancelTimer = () => {};
  let stopped = false;

  const setAllowed = (next: boolean) => {
    if (allowed === next) return;
    allowed = next;
    onChange(next);
  };
  const clearTimer = () => {
    cancelTimer();
    cancelTimer = () => {};
    armed = false;
  };
  // Re-evaluate: not ready closes Approve at once; ready starts the delay.
  const evaluate = () => {
    if (stopped) return;
    const ready = pageVisible && targets.every((target) => visible[target] === true);
    if (!ready) {
      clearTimer();
      setAllowed(false);
    } else if (!allowed && !armed) {
      armed = true;
      const id = setTimeout(() => {
        armed = false;
        setAllowed(true);
      }, delay);
      cancelTimer = () => clearTimeout(id);
    }
  };

  return {
    get allowed() {
      return allowed;
    },
    report(target, isVisible) {
      visible[target] = isVisible;
      evaluate();
    },
    setPageVisible(next) {
      pageVisible = next;
      evaluate();
    },
    rearm() {
      clearTimer();
      setAllowed(false);
      evaluate();
    },
    stop() {
      stopped = true;
      clearTimer();
    },
  };
}

/** True inside a frame. A page that cannot compare itself with the top counts as framed. */
export function isFramed(): boolean {
  try {
    return window.self !== window.top;
  } catch {
    return true;
  }
}

export interface FrameVisibilityBinding {
  readonly allowed: boolean;
  /** Pull pending reports now; true only if Approve is still allowed. */
  confirmNow(): boolean;
  stop(): void;
}

export interface FrameVisibilityTargets {
  /** The whole approval view. */
  view: Element;
  /** The row holding Approve and Cancel. */
  actions: Element;
}

/**
 * Watch the view and its action row with IntersectionObserver (v2 where
 * supported) and the window's blur and visibility events, and feed a guard.
 */
export function watchFrameVisibility(
  targets: FrameVisibilityTargets,
  onChange: (allowed: boolean) => void,
): FrameVisibilityBinding {
  const observer = new IntersectionObserver(
    (entries) => feed(entries),
    {
      threshold: [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, MIN_VISIBLE_RATIO, 1],
      trackVisibility: true,
      delay: VISIBILITY_TRACKING_DELAY_MS,
    } as IntersectionObserverInit,
  );
  // `trackVisibility` makes the browser report `isVisible`; the property on
  // the observer tells us whether it actually took effect.
  const trackVisibility = (observer as IntersectionObserver & { trackVisibility?: boolean }).trackVisibility === true;
  const guard = createVisibilityGuard({ targets: ['view', 'actions'], onChange });

  function feed(entries: readonly IntersectionObserverEntry[]) {
    for (const entry of entries) {
      const name = entry.target === targets.view ? 'view' : entry.target === targets.actions ? 'actions' : null;
      if (name === null) continue;
      const state = targetState(entry as VisibilityEntry, trackVisibility, { width: window.innerWidth, height: window.innerHeight });
      guard.report(name, state !== 'obscured');
    }
  }

  // A frame that has not been clicked yet is not focused, so focus is not
  // required; losing focus or visibility starts the delay again.
  const pageVisibleNow = () => document.visibilityState === 'visible';
  const onBlurOrVisibility = () => {
    guard.rearm();
    guard.setPageVisible(pageVisibleNow());
  };
  window.addEventListener('blur', onBlurOrVisibility);
  document.addEventListener('visibilitychange', onBlurOrVisibility);
  guard.setPageVisible(pageVisibleNow());
  observer.observe(targets.view);
  observer.observe(targets.actions);

  return {
    get allowed() {
      return guard.allowed;
    },
    confirmNow() {
      feed(observer.takeRecords());
      return guard.allowed;
    },
    stop() {
      window.removeEventListener('blur', onBlurOrVisibility);
      document.removeEventListener('visibilitychange', onBlurOrVisibility);
      observer.disconnect();
      guard.stop();
    },
  };
}
