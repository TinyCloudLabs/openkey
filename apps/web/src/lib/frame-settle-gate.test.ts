// TC-2320: a v1 embed has no layout-ready message, so its Approve is armed by the frame's own size going quiet:
// QUIET_MS without a resize, but never later than CEILING_MS from the first display or from each new resize post.
// Timers, animation frames and the sampled frame/Approve box are injected: no real clock or DOM runs here.
// TC-3185: after the quiet period Approve also needs STABLE_FRAMES consecutive unchanged frames, and a resize after
// arming disarms it again.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  createFrameSettleGate,
  FRAME_SETTLE_CEILING_GRACE_MS,
  FRAME_SETTLE_CEILING_MS,
  FRAME_SETTLE_QUIET_MS,
  FRAME_SETTLE_STABLE_FRAMES,
} from './frame-settle-gate';

/** A manual clock: `advance` fires due timers in order, like setTimeout would. */
function clock() {
  let now = 0;
  let nextId = 1;
  const timers = new Map<number, { at: number; run: () => void }>();
  return {
    schedule: (run: () => void, ms: number) => {
      const id = nextId++;
      timers.set(id, { at: now + ms, run });
      return () => { timers.delete(id); };
    },
    advance(ms: number) {
      const end = now + ms;
      for (;;) {
        const due = [...timers.entries()].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        now = due[1].at;
        timers.delete(due[0]);
        due[1].run();
      }
      now = end;
    },
    pending: () => timers.size,
  };
}

/** Manual animation frames: `tick` runs every callback queued so far, like one rAF round. */
function frames() {
  let nextId = 1;
  const queue = new Map<number, () => void>();
  return {
    nextFrame: (run: () => void) => {
      const id = nextId++;
      queue.set(id, run);
      return () => { queue.delete(id); };
    },
    tick() {
      const batch = [...queue.entries()];
      queue.clear();
      for (const [, run] of batch) run();
    },
    pending: () => queue.size,
  };
}

function gate() {
  const c = clock();
  const states: boolean[] = [];
  // These timing tests assume the frame is already stable: every frame runs at once, over an unchanging sample.
  const g = createFrameSettleGate({
    schedule: c.schedule,
    nextFrame: (run) => { run(); return () => {}; },
    sample: () => [0],
    onChange: (settled) => states.push(settled),
  });
  return { c, g, states };
}

/** Resizes every 100ms from the first resize; Approve must be off the whole time until CEILING_MS after that first resize. */
function resizeForeverUntilCeiling(c: ReturnType<typeof clock>, g: ReturnType<typeof createFrameSettleGate>) {
  g.resized();
  expect(g.settled()).toBe(false);
  for (let elapsed = 100; elapsed < FRAME_SETTLE_CEILING_MS; elapsed += 100) {
    c.advance(100);
    g.resized();
    expect(g.settled()).toBe(false);
  }
  c.advance(100); // the ceiling fires here, CEILING_MS after the first resize; its stable check needs a frame
  expect(g.settled()).toBe(false);
}

/** Real (manual) frames and a settable sample, for the observed-stability behaviour. */
function observed() {
  const c = clock();
  const f = frames();
  const states: boolean[] = [];
  let current: number[] = [400, 400, 0, 0, 100, 40];
  const g = createFrameSettleGate({
    schedule: c.schedule,
    nextFrame: f.nextFrame,
    sample: () => current,
    onChange: (settled) => states.push(settled),
  });
  return { c, f, g, states, move: (next: number[]) => { current = next; } };
}

describe('the settle gate', () => {
  test('blocks until the frame has been quiet for QUIET_MS after the review is shown, then arms', () => {
    const { c, g } = gate();
    g.show();
    expect(g.settled()).toBe(false);
    c.advance(FRAME_SETTLE_QUIET_MS - 1);
    expect(g.settled()).toBe(false);
    c.advance(1);
    expect(g.settled()).toBe(true);
  });

  test('every resize restarts the quiet timer: it arms QUIET_MS after the LAST one, not the first', () => {
    const { c, g } = gate();
    g.show();
    for (let frame = 0; frame < 10; frame += 1) { c.advance(16); g.resized(); }
    c.advance(FRAME_SETTLE_QUIET_MS - 1);
    expect(g.settled()).toBe(false);
    c.advance(1);
    expect(g.settled()).toBe(true);
  });

  test('a frame that never stops resizing is armed at the ceiling, never later', () => {
    const { c, g } = gate();
    g.show();
    let elapsed = 0;
    while (elapsed + 16 < FRAME_SETTLE_CEILING_MS) { c.advance(16); elapsed += 16; g.resized(); expect(g.settled()).toBe(false); }
    c.advance(FRAME_SETTLE_CEILING_MS - elapsed);
    expect(g.settled()).toBe(true);
  });

  test('a parent that never resizes arms after QUIET_MS alone', () => {
    const { c, g } = gate();
    g.show();
    c.advance(FRAME_SETTLE_QUIET_MS);
    expect(g.settled()).toBe(true);
  });

  test('a later resize blocks again, and arms again after QUIET_MS of quiet', () => {
    const { c, g, states } = gate();
    g.show();
    c.advance(FRAME_SETTLE_QUIET_MS);
    expect(g.settled()).toBe(true);
    g.posted();
    expect(g.settled()).toBe(false);
    c.advance(FRAME_SETTLE_QUIET_MS);
    expect(g.settled()).toBe(true);
    expect(states).toEqual([true, false, true]);
  });

  test('a later resize that never goes quiet is armed at the ceiling counted from that post', () => {
    const { c, g } = gate();
    g.show();
    c.advance(FRAME_SETTLE_QUIET_MS);
    g.posted();
    const posted = FRAME_SETTLE_CEILING_MS;
    let elapsed = 0;
    while (elapsed + 16 < posted) { c.advance(16); elapsed += 16; g.resized(); expect(g.settled()).toBe(false); }
    c.advance(posted - elapsed);
    expect(g.settled()).toBe(true);
  });

  test('onChange fires only when the state flips, not on every resize', () => {
    const { c, g, states } = gate();
    g.show();
    g.resized(); g.resized(); g.resized();
    expect(states).toEqual([]);
    c.advance(FRAME_SETTLE_QUIET_MS);
    expect(states).toEqual([true]);
  });

  test('a resize before the review is shown is ignored (nothing to arm yet)', () => {
    const { c, g } = gate();
    g.resized();
    c.advance(FRAME_SETTLE_CEILING_MS * 2);
    expect(g.settled()).toBe(false);
    g.show();
    c.advance(FRAME_SETTLE_QUIET_MS);
    expect(g.settled()).toBe(true);
  });

  test('destroy cancels every timer and nothing fires afterwards', () => {
    const { c, g, states } = gate();
    g.show();
    g.destroy();
    expect(c.pending()).toBe(0);
    c.advance(FRAME_SETTLE_CEILING_MS * 2);
    expect(states).toEqual([]);
    g.resized();
    g.posted();
    expect(c.pending()).toBe(0);
  });

  test('a resize after Approve is enabled disarms it, and it re-arms only after quiet plus stable frames', () => {
    const { c, f, g, states } = observed();
    g.show();
    c.advance(FRAME_SETTLE_QUIET_MS);
    for (let i = 0; i < FRAME_SETTLE_STABLE_FRAMES; i += 1) f.tick();
    expect(g.settled()).toBe(true);
    g.resized();
    expect(g.settled()).toBe(false);
    expect(states).toEqual([true, false]);
    c.advance(FRAME_SETTLE_QUIET_MS - 1);
    f.tick(); f.tick(); f.tick();
    expect(g.settled()).toBe(false); // frames before the quiet period ends do not count
    c.advance(1);
    for (let i = 0; i < FRAME_SETTLE_STABLE_FRAMES - 1; i += 1) { f.tick(); expect(g.settled()).toBe(false); }
    f.tick();
    expect(g.settled()).toBe(true);
    expect(states).toEqual([true, false, true]);
  });

  test('a sample that keeps changing after the quiet period delays arming (it is not skipped); arming is on the third stable frame', () => {
    const { c, f, g, move } = observed();
    g.show();
    c.advance(FRAME_SETTLE_QUIET_MS);
    move([400, 420, 0, 0, 100, 40]);
    f.tick(); // changed
    f.tick(); // 1 stable
    move([400, 440, 0, 0, 100, 40]);
    f.tick(); // changed: the count restarts
    c.advance(FRAME_SETTLE_CEILING_MS - FRAME_SETTLE_QUIET_MS - 1); // plenty of time passes: time alone does not arm
    expect(g.settled()).toBe(false);
    f.tick(); // 1 stable
    f.tick(); // 2 stable
    expect(g.settled()).toBe(false);
    f.tick(); // 3 stable
    expect(g.settled()).toBe(true);
  });

  test('stalled time does not skip the frame check: the quiet timer firing late still waits for stable frames', () => {
    const { c, f, g } = observed();
    g.show();
    c.advance(FRAME_SETTLE_QUIET_MS + 400); // a stall: the timer fires late, no frame ran meanwhile
    expect(g.settled()).toBe(false);
    f.tick(); f.tick();
    expect(g.settled()).toBe(false);
    f.tick();
    expect(g.settled()).toBe(true);
  });

  test("a change of Approve's own box alone (frame size unchanged) also restarts the stable-frame count", () => {
    const { c, f, g, move } = observed();
    g.show();
    c.advance(FRAME_SETTLE_QUIET_MS);
    f.tick(); f.tick(); // two stable frames
    move([400, 400, 20, 0, 100, 40]); // only Approve's top moved
    f.tick();
    f.tick(); f.tick();
    expect(g.settled()).toBe(false);
    f.tick();
    expect(g.settled()).toBe(true);
  });

  test('at the ceiling, arming needs one stable check (two equal consecutive samples), not just the timer', () => {
    const { c, f, g } = observed();
    g.show();
    let elapsed = 0;
    while (elapsed + 16 < FRAME_SETTLE_CEILING_MS) { c.advance(16); elapsed += 16; g.resized(); }
    c.advance(FRAME_SETTLE_CEILING_MS - elapsed);
    expect(g.settled()).toBe(false); // the ceiling fired, but no frame has confirmed stability yet
    f.tick();
    expect(g.settled()).toBe(true);
  });

  test('at the ceiling, a resize does not cancel the stable check, and a sample that never settles is armed by the first frame after the grace', () => {
    const { c, f, g, move } = observed();
    g.show();
    c.advance(FRAME_SETTLE_CEILING_MS);
    expect(g.settled()).toBe(false);
    for (let i = 1; i <= 5; i += 1) {
      g.resized();
      move([400, 400 + i, 0, 0, 100, 40]);
      f.tick();
      expect(g.settled()).toBe(false); // changing on every frame, still inside the grace
    }
    c.advance(FRAME_SETTLE_CEILING_GRACE_MS);
    expect(g.settled()).toBe(false); // the grace is over, but arming waits for an observed frame (a stall delays, not skips)
    move([400, 999, 0, 0, 100, 40]);
    f.tick();
    expect(g.settled()).toBe(true);
  });

  test('a host that resizes every 100ms after Approve was armed at quiet: the first resize disarms, and the ceiling re-arms it', () => {
    const { c, f, g } = observed();
    g.show();
    c.advance(FRAME_SETTLE_QUIET_MS);
    for (let i = 0; i < FRAME_SETTLE_STABLE_FRAMES; i += 1) f.tick();
    expect(g.settled()).toBe(true);
    resizeForeverUntilCeiling(c, g);
    f.tick(); // one stable frame at the ceiling arms it
    expect(g.settled()).toBe(true);
  });

  test('the same after the ceiling itself had armed it', () => {
    const { c, f, g } = observed();
    g.show();
    resizeForeverUntilCeiling(c, g);
    f.tick();
    expect(g.settled()).toBe(true);
    resizeForeverUntilCeiling(c, g);
    f.tick();
    expect(g.settled()).toBe(true);
  });

  test('posted() cancels pending frame callbacks and starts a fresh quiet period and ceiling', () => {
    const { c, f, g } = observed();
    g.show();
    c.advance(FRAME_SETTLE_QUIET_MS);
    expect(f.pending()).toBe(1);
    g.posted();
    expect(f.pending()).toBe(0);
    f.tick(); f.tick(); f.tick();
    expect(g.settled()).toBe(false);
    c.advance(FRAME_SETTLE_CEILING_MS);
    expect(f.pending()).toBe(1);
    f.tick();
    expect(g.settled()).toBe(true);
  });

  test('destroy cancels pending frame callbacks: nothing arms afterwards', () => {
    const { c, f, g, states } = observed();
    g.show();
    c.advance(FRAME_SETTLE_QUIET_MS);
    expect(f.pending()).toBe(1);
    g.destroy();
    expect(f.pending()).toBe(0);
    f.tick(); f.tick(); f.tick();
    c.advance(FRAME_SETTLE_CEILING_MS * 2);
    f.tick();
    expect(states).toEqual([]);
    expect(g.settled()).toBe(false);
  });
});
