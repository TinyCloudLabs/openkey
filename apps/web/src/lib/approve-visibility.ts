// A sign page inside another page's frame honours the one-passkey cover only while its Approve button is plainly in
// view. The browser's intersection observer v2 reports whether a button is fully inside the viewport, not covered by
// another element and not faded or transformed (`isVisible`). The cover is used only after the button has been
// reported that way without a break for `COVER_VISIBLE_MS`, and only while the latest report still says so. When the
// cover is not honoured the page names no flow, fetches the offer again and asks for the approval passkey on that tap
// as it does without a cover. A page that is not framed has nothing to overlay it and is not gated. A sample comes at
// most every `SAMPLE_DELAY_MS`, so an element placed over the button between two samples is not seen until the next one.

import type { ApprovalPasskeyNeed } from './approval-passkey';

export const COVER_VISIBLE_MS = 500;
export const SAMPLE_DELAY_MS = 100;

/** The parts of an `IntersectionObserverEntry` the tracker reads; `isVisible` exists only with observer v2. */
export interface VisibilityEntryLike {
  isIntersecting: boolean;
  isVisible?: boolean;
}

export interface VisibilityObserver {
  observe(target: Element): void;
  disconnect(): void;
}

/** Builds the observer, or returns null where observer v2 is not available. */
export type VisibilityObserverFactory = (callback: (entries: readonly VisibilityEntryLike[]) => void) => VisibilityObserver | null;

export interface ApproveVisibility {
  /** False where the cover can never be honoured (framed, without observer v2): the page then names no flow at all. */
  readonly coverUsable: boolean;
  /** Observes this Approve button, or stops observing when it is null. A new button starts from not seen. */
  watch(button: Element | null): void;
  /** Starts the visible window over: Approve became actionable again or the request changed. */
  restart(): void;
  /** Whether a click on Approve now may use the cover. */
  honoursCover(): boolean;
}

/** True when this page runs inside another page's frame; a parent that cannot be read counts as a frame. */
export function isFramed(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    return window.self !== window.top;
  } catch {
    return true;
  }
}

const browserObserver: VisibilityObserverFactory = (callback) => {
  if (typeof IntersectionObserver === 'undefined' || typeof IntersectionObserverEntry === 'undefined') return null;
  if (!('isVisible' in IntersectionObserverEntry.prototype)) return null;
  // The v2 options are not in every TypeScript DOM lib.
  const options = { threshold: 1.0, trackVisibility: true, delay: SAMPLE_DELAY_MS } as IntersectionObserverInit;
  return new IntersectionObserver((entries) => callback(entries), options);
};

export function createApproveVisibility(options: {
  framed?: boolean;
  createObserver?: VisibilityObserverFactory;
  now?: () => number;
} = {}): ApproveVisibility {
  const framed = options.framed ?? isFramed();
  const now = options.now ?? (() => performance.now());
  const createObserver = options.createObserver ?? browserObserver;
  let observer: VisibilityObserver | null = null;
  let supported: boolean | null = null;
  let latestVisible = false;
  let visibleSince: number | null = null;

  function observerOrNull(): VisibilityObserver | null {
    if (supported === false) return null;
    if (observer) return observer;
    observer = createObserver((entries) => {
      const latest = entries[entries.length - 1];
      if (!latest) return;
      latestVisible = latest.isIntersecting && latest.isVisible === true;
      if (!latestVisible) visibleSince = null;
      else if (visibleSince === null) visibleSince = now();
    });
    supported = observer !== null;
    return observer;
  }

  // Not framed: nothing to gate, so nothing is created. Framed: whether the browser has observer v2 is known now.
  const coverUsable = !framed || observerOrNull() !== null;

  return {
    coverUsable,
    watch(button) {
      latestVisible = false;
      visibleSince = null;
      if (!framed) return;
      const current = observerOrNull();
      if (!current) return;
      current.disconnect();
      if (button) current.observe(button);
    },
    restart() {
      visibleSince = latestVisible ? now() : null;
    },
    honoursCover() {
      if (!framed) return true;
      if (!coverUsable) return false;
      return latestVisible && visibleSince !== null && now() - visibleSince >= COVER_VISIBLE_MS;
    },
  };
}

/**
 * True when the offer asks for no passkey only because this flow's sign-in covers it, and Approve has not been in plain
 * view long enough for that cover to count. The page then asks for the passkey on that tap: it fetches the offer again
 * without the flow id and goes on to the passkey prompt.
 */
export function coverNotHonoured(need: ApprovalPasskeyNeed | null, visibility: ApproveVisibility): boolean {
  return need !== null && !need.required && need.flowCover === true && !visibility.honoursCover();
}

/**
 * What the review put in front of the owner for one request: the preview input (key, message, selection, chosen
 * expiry, allowed extra permissions) or the exact-byte offer input, the exact bytes the preview sealed (empty on the
 * exact-byte path, whose bytes are the message in the input) and the owner's renewal lease.
 */
export type ReviewSnapshot = { input: string; signedMessage: string; renewalLeaseMs: number | null };

/** The snapshot of a request, or null when it has no input: nothing was shown that a refetched offer could match. */
export function reviewSnapshot(
  input: string | null | undefined,
  signedMessage: string,
  renewalLeaseMs: number | null,
): ReviewSnapshot | null {
  return input ? { input, signedMessage, renewalLeaseMs } : null;
}

/**
 * True when a refetched offer is for exactly the request the owner saw at the tap. Only then does that tap go on to
 * the passkey prompt; any difference, and a missing snapshot on either side, leaves the page showing the new request
 * and waiting for a new tap.
 */
export function sameReview(shown: ReviewSnapshot | null, fresh: ReviewSnapshot | null): boolean {
  return shown !== null
    && fresh !== null
    && shown.input === fresh.input
    && shown.signedMessage === fresh.signedMessage
    && shown.renewalLeaseMs === fresh.renewalLeaseMs;
}
