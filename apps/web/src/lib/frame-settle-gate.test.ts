// TC-2320: a v1 embed has no layout-ready message, so its Approve is armed by the frame's own size going quiet:
// QUIET_MS without a resize, but never later than CEILING_MS from the first display or from each new resize post.
// Timers are injected: no real clock runs here.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { createFrameSettleGate, FRAME_SETTLE_CEILING_MS, FRAME_SETTLE_QUIET_MS } from './frame-settle-gate';

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

function gate() {
  const c = clock();
  const states: boolean[] = [];
  const g = createFrameSettleGate({ schedule: c.schedule, onChange: (settled) => states.push(settled) });
  return { c, g, states };
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
});
