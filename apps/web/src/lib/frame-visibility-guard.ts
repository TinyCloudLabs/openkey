// Visibility guard for the approval view while it is shown inside a frame.
//
// Approve is available only after every watched part of the view (the summary
// and the Approve button) has been fully visible and uncovered for a
// continuous delay, with the page visible. Any loss of
// visibility, window blur or tab hide starts the delay again. A click is
// accepted only if the newest visibility reports still say visible.
//
// Where the browser supports IntersectionObserver v2 (`trackVisibility`),
// `entry.isVisible` is required: it is the field that turns false when the
// element is covered, faded or transformed. `isIntersecting` stays true in
// those cases. Browsers without v2 are checked for cropping and scrolling
// away (`isIntersecting` and the ratio) plus the delay.

export const VISIBILITY_ENABLE_DELAY_MS = 600;
export const VISIBILITY_TRACKING_DELAY_MS = 100;
export const MIN_VISIBLE_RATIO = 0.99;

/** The fields of an `IntersectionObserverEntry` the guard reads. */
export interface VisibilityEntry {
  isIntersecting: boolean;
  intersectionRatio: number;
  /** Present only where the browser supports IntersectionObserver v2. */
  isVisible?: boolean;
}

export interface VisibilityGuard {
  /** True once every target has stayed visible for the enable delay. */
  readonly allowed: boolean;
  /** `minRatio` lowers the bar for a target taller than the frame's own viewport. */
  report(target: string, entry: VisibilityEntry, minRatio?: number): void;
  /** The page or window lost or regained visibility/focus. */
  setPageVisible(visible: boolean): void;
  /** Start the delay again from now. */
  rearm(): void;
  stop(): void;
}

export interface VisibilityGuardOptions {
  targets: readonly string[];
  /** The browser reports `isVisible` (IntersectionObserver v2). */
  trackVisibility: boolean;
  onChange: (allowed: boolean) => void;
  enableDelayMs?: number;
}

export function isEntryVisible(entry: VisibilityEntry, trackVisibility: boolean, minRatio = MIN_VISIBLE_RATIO): boolean {
  if (!entry.isIntersecting || entry.intersectionRatio < minRatio) return false;
  return !trackVisibility || entry.isVisible === true;
}

export function createVisibilityGuard(options: VisibilityGuardOptions): VisibilityGuard {
  const { targets, trackVisibility, onChange } = options;
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
    report(target, entry, minRatio) {
      visible[target] = isEntryVisible(entry, trackVisibility, minRatio);
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

export interface FrameVisibilityTarget {
  name: string;
  element: Element;
  /**
   * Ratio this target must reach. Defaults to `MIN_VISIBLE_RATIO`. A target
   * taller than the frame's own viewport can never be fully inside it, so the
   * caller may ask for the share of it that fits.
   */
  minRatio?: () => number;
}

/**
 * Watch `targets` with IntersectionObserver (v2 where supported) and the
 * window's focus and visibility events, and feed a guard.
 */
export function watchFrameVisibility(
  targets: readonly FrameVisibilityTarget[],
  onChange: (allowed: boolean) => void,
): FrameVisibilityBinding {
  const byElement = new Map<Element, FrameVisibilityTarget>(targets.map((target) => [target.element, target]));
  // `trackVisibility` makes the browser report `isVisible`; the property on
  // the observer tells us whether it actually took effect.
  const observer = new IntersectionObserver(
    (entries) => feed(entries),
    {
      threshold: [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, MIN_VISIBLE_RATIO, 1],
      trackVisibility: true,
      delay: VISIBILITY_TRACKING_DELAY_MS,
    } as IntersectionObserverInit,
  );
  const trackVisibility = (observer as IntersectionObserver & { trackVisibility?: boolean }).trackVisibility === true;
  const guard = createVisibilityGuard({ targets: targets.map((target) => target.name), trackVisibility, onChange });

  function feed(entries: readonly IntersectionObserverEntry[]) {
    for (const entry of entries) {
      const target = byElement.get(entry.target);
      if (target !== undefined) guard.report(target.name, entry as VisibilityEntry, target.minRatio?.());
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
  for (const target of targets) observer.observe(target.element);

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
