// TC-2320: a v1 embed has no layout-ready message from the host, so it cannot know when the SDK modal has finished
// animating the frame (the modal opens it at 400px and transitions its height over 200ms, inside a centred card:
// a height change of D moves Approve by D/2). The frame can see its own size, so Approve is armed once that size has
// been quiet for QUIET_MS AND the frame size and Approve's own box were then observed unchanged for STABLE_FRAMES
// consecutive animation frames (TC-3185: elapsed time alone fires mid-animation after a stalled main thread). It is
// never held later than CEILING_MS from the first display or from each new resize post, so it can never stay off.
// A resize after Approve is enabled disarms it again. A page-level slide that moves the frame without resizing it
// cannot be seen from inside.

/** No resize of the frame for this long: the transition (200ms) has finished, with a frame of margin. */
export const FRAME_SETTLE_QUIET_MS = 300;
/** The longest Approve waits for quiet, counted from the first display and from each new resize post. */
export const FRAME_SETTLE_CEILING_MS = 1500;
/** After the quiet period, the sample must be unchanged for this many consecutive animation frames. */
export const FRAME_SETTLE_STABLE_FRAMES = 3;
/** At the ceiling, one unchanged animation frame (two equal consecutive samples) is enough. */
export const FRAME_SETTLE_CEILING_STABLE_FRAMES = 1;
/**
 * At the ceiling, the stable check gives up this long after the ceiling: the next animation frame that runs then arms
 * Approve, stable or not, so a sample that changes on every frame cannot hold Approve off forever.
 */
export const FRAME_SETTLE_CEILING_GRACE_MS = 100;

export interface FrameSettleGate {
  /** The review is on screen: start waiting (the first call only). */
  show(): void;
  /** The widget posted a new height to the host, which will animate the frame again. */
  posted(): void;
  /** The frame's own size changed (window resize or a ResizeObserver tick): disarms and restarts the quiet period. */
  resized(): void;
  settled(): boolean;
  destroy(): void;
}

export function createFrameSettleGate(options: {
  /** Runs `run` after `ms`; returns a cancel function. Injected so tests need no real clock. */
  schedule: (run: () => void, ms: number) => () => void;
  /** Runs `run` on the next animation frame; returns a cancel function. Injected so tests need no real frames. */
  nextFrame: (run: () => void) => () => void;
  /** The frame size and Approve's box right now; two equal samples mean nothing moved between them. */
  sample: () => readonly number[];
  /** Called only when the settled state flips. */
  onChange: (settled: boolean) => void;
}): FrameSettleGate {
  const { schedule, nextFrame, sample, onChange } = options;
  let shown = false;
  let destroyed = false;
  let settled = false;
  // The ceiling has fired: its bounded stable check is running and a resize must not cancel it.
  let atCeiling = false;
  let cancelQuiet: (() => void) | undefined;
  let cancelCeiling: (() => void) | undefined;
  let cancelFrame: (() => void) | undefined;
  let cancelGrace: (() => void) | undefined;

  const set = (next: boolean) => {
    if (settled === next) return;
    settled = next;
    onChange(next);
  };
  const stopFrames = () => {
    cancelFrame?.();
    cancelGrace?.();
    cancelFrame = undefined;
    cancelGrace = undefined;
  };
  const arm = () => {
    cancelQuiet?.();
    cancelCeiling?.();
    stopFrames();
    cancelQuiet = undefined;
    cancelCeiling = undefined;
    atCeiling = false;
    set(true);
  };
  // Arms after `needed` consecutive animation frames whose sample equals the one before. A stalled main thread
  // delays the frames, so it delays arming and never skips it. `graceMs`, when given, bounds the wait: once it has
  // elapsed the next frame that runs arms regardless, so a sample that changes on every frame cannot hold Approve off
  // forever (a stall still only delays that frame; arming always follows an observed frame).
  const armWhenStable = (needed: number, graceMs?: number) => {
    stopFrames();
    let last = sample().join(',');
    let stable = 0;
    let overdue = false;
    if (graceMs !== undefined) cancelGrace = schedule(() => { overdue = true; }, graceMs);
    const tick = () => {
      cancelFrame = undefined;
      const now = sample().join(',');
      if (now === last) stable += 1;
      else { stable = 0; last = now; }
      if (stable >= needed || overdue) arm();
      else cancelFrame = nextFrame(tick);
    };
    cancelFrame = nextFrame(tick);
  };
  const restartQuiet = () => {
    cancelQuiet?.();
    stopFrames();
    cancelQuiet = schedule(() => {
      cancelQuiet = undefined;
      armWhenStable(FRAME_SETTLE_STABLE_FRAMES);
    }, FRAME_SETTLE_QUIET_MS);
  };
  const startCeiling = () => {
    cancelCeiling?.();
    atCeiling = false;
    cancelCeiling = schedule(() => {
      cancelCeiling = undefined;
      cancelQuiet?.();
      cancelQuiet = undefined;
      atCeiling = true;
      armWhenStable(FRAME_SETTLE_CEILING_STABLE_FRAMES, FRAME_SETTLE_CEILING_GRACE_MS);
    }, FRAME_SETTLE_CEILING_MS);
  };

  return {
    show() {
      if (shown || destroyed) return;
      shown = true;
      startCeiling();
      restartQuiet();
    },
    posted() {
      if (!shown || destroyed) return;
      // A new height was posted: block again, with a fresh ceiling, until the frame has been quiet.
      set(false);
      startCeiling();
      restartQuiet();
    },
    resized() {
      if (!shown || destroyed || atCeiling) return;
      set(false);
      restartQuiet();
    },
    settled: () => settled,
    destroy() {
      destroyed = true;
      cancelQuiet?.();
      cancelCeiling?.();
      stopFrames();
      cancelQuiet = undefined;
      cancelCeiling = undefined;
    },
  };
}
