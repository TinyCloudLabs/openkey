// TC-2320: a v1 embed has no layout-ready message from the host, so it cannot know when the SDK modal has finished
// animating the frame (the modal opens it at 400px and transitions its height over 200ms, inside a centred card:
// a height change of D moves Approve by D/2). The frame can see its own size, so Approve is armed when that size
// has been quiet for QUIET_MS, and never later than CEILING_MS from the first display or from each new resize post,
// so it can never stay off. A page-level slide that moves the frame without resizing it cannot be seen from inside.

/** No resize of the frame for this long: the transition (200ms) has finished, with a frame of margin. */
export const FRAME_SETTLE_QUIET_MS = 300;
/** The longest Approve waits, counted from the first display and from each new resize post. */
export const FRAME_SETTLE_CEILING_MS = 1500;

export interface FrameSettleGate {
  /** The review is on screen: start waiting (the first call only). */
  show(): void;
  /** The widget posted a new height to the host, which will animate the frame again. */
  posted(): void;
  /** The frame's own size changed (window resize or a ResizeObserver tick). */
  resized(): void;
  settled(): boolean;
  destroy(): void;
}

export function createFrameSettleGate(options: {
  /** Runs `run` after `ms`; returns a cancel function. Injected so tests need no real clock. */
  schedule: (run: () => void, ms: number) => () => void;
  /** Called only when the settled state flips. */
  onChange: (settled: boolean) => void;
}): FrameSettleGate {
  const { schedule, onChange } = options;
  let shown = false;
  let destroyed = false;
  let settled = false;
  let cancelQuiet: (() => void) | undefined;
  let cancelCeiling: (() => void) | undefined;

  const set = (next: boolean) => {
    if (settled === next) return;
    settled = next;
    onChange(next);
  };
  const arm = () => {
    cancelQuiet?.();
    cancelCeiling?.();
    cancelQuiet = undefined;
    cancelCeiling = undefined;
    set(true);
  };
  const restartQuiet = () => {
    cancelQuiet?.();
    cancelQuiet = schedule(arm, FRAME_SETTLE_QUIET_MS);
  };

  return {
    show() {
      if (shown || destroyed) return;
      shown = true;
      cancelCeiling = schedule(arm, FRAME_SETTLE_CEILING_MS);
      restartQuiet();
    },
    posted() {
      if (!shown || destroyed) return;
      // A new height was posted: block again, with a fresh ceiling, until the frame has been quiet.
      set(false);
      cancelCeiling?.();
      cancelCeiling = schedule(arm, FRAME_SETTLE_CEILING_MS);
      restartQuiet();
    },
    resized() {
      if (!shown || destroyed) return;
      restartQuiet();
    },
    settled: () => settled,
    destroy() {
      destroyed = true;
      cancelQuiet?.();
      cancelCeiling?.();
      cancelQuiet = undefined;
      cancelCeiling = undefined;
    },
  };
}
