// A click on Approve that arrives right after the control became actionable is ignored. It makes a click land only
// after Approve has been shown for half a second. The 500 ms restarts every time Approve becomes actionable again.

/** How long Approve must have been actionable before a click counts. */
export const APPROVE_SETTLE_MS = 500;

export interface ApproveGuard {
  /** Records whether Approve is actionable now. Turning actionable starts the window; staying actionable does not. */
  track(actionable: boolean): void;
  /** True once Approve has been actionable for the whole window. */
  ready(): boolean;
}

/** `clock` is a monotonic millisecond clock; a deferred timer cannot shorten the window. */
export function createApproveGuard(clock: () => number = () => performance.now()): ApproveGuard {
  let since: number | null = null;
  return {
    track(actionable) {
      if (!actionable) since = null;
      else if (since === null) since = clock();
    },
    ready() {
      return since !== null && clock() - since >= APPROVE_SETTLE_MS;
    },
  };
}

/**
 * The guard for a sign page, present only where another page can sit over it: when the page runs inside a frame. A
 * page that cannot read its parent is framed too.
 */
export function approveGuardForFrame(): ApproveGuard | undefined {
  try {
    return window.self !== window.top ? createApproveGuard() : undefined;
  } catch {
    return createApproveGuard();
  }
}
