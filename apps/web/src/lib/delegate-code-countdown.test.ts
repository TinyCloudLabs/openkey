// @ts-expect-error bun:test is provided by the Bun runtime
import { describe, expect, test } from 'bun:test';
import {
  CODE_EXPIRED_TEXT,
  CODE_ONE_MINUTE_ANNOUNCEMENT,
  formatCodeCountdown,
  remainingFromExpiry,
  startCodeCountdown,
  type CodeCountdownClock,
  type CodeCountdownSnapshot,
} from './delegate-code-countdown';

// Advances in 250 ms steps, the same cadence the real interval uses.
function fakeClock() {
  let now = 0;
  let nextHandle = 1;
  const intervals = new Map<number, () => void>();
  const clock: CodeCountdownClock = {
    now: () => now,
    setInterval: (callback) => {
      const handle = nextHandle++;
      intervals.set(handle, callback);
      return handle;
    },
    clearInterval: (handle) => {
      intervals.delete(handle as number);
    },
  };
  return {
    clock,
    activeIntervals: () => intervals.size,
    advance(ms: number) {
      const end = now + ms;
      while (now < end) {
        now = Math.min(end, now + 250);
        for (const callback of [...intervals.values()]) callback();
      }
    },
  };
}

function run(deadline: number, clock: ReturnType<typeof fakeClock>) {
  const snapshots: CodeCountdownSnapshot[] = [];
  const stop = startCodeCountdown({
    deadline,
    clock: clock.clock,
    onUpdate: (snapshot) => snapshots.push(snapshot),
  });
  return { snapshots, stop, last: () => snapshots[snapshots.length - 1] };
}

describe('formatCodeCountdown', () => {
  test('formats 5:00, 0:59, and 0:00 at the boundaries', () => {
    expect(formatCodeCountdown(300_000)).toBe('5:00');
    expect(formatCodeCountdown(59_000)).toBe('0:59');
    expect(formatCodeCountdown(0)).toBe('0:00');
  });

  test('rounds partial seconds up so 0:00 never shows while valid', () => {
    expect(formatCodeCountdown(1)).toBe('0:01');
    expect(formatCodeCountdown(59_001)).toBe('1:00');
  });

  test('never shows negative time', () => {
    expect(formatCodeCountdown(-5_000)).toBe('0:00');
    expect(formatCodeCountdown(Number.NaN)).toBe('0:00');
  });
});

describe('remainingFromExpiry', () => {
  test('returns the milliseconds left until the server instant', () => {
    expect(remainingFromExpiry('2026-10-05T00:05:00.000Z', Date.parse('2026-10-05T00:00:00.000Z'))).toBe(300_000);
  });

  test('clamps an already-passed instant to zero', () => {
    expect(remainingFromExpiry('2026-10-05T00:00:00.000Z', Date.parse('2026-10-05T00:05:00.000Z'))).toBe(0);
  });

  test('returns null for an unparseable instant', () => {
    expect(remainingFromExpiry('not a date', 0)).toBeNull();
  });
});

describe('startCodeCountdown', () => {
  test('starts at the remaining time and ticks down by whole seconds', () => {
    const fake = fakeClock();
    const { last, stop } = run(300_000, fake);
    expect(last().text).toBe('Code valid for 5:00');
    fake.advance(1_000);
    expect(last().text).toBe('Code valid for 4:59');
    stop();
  });

  test('shows 0:59 at one minute minus a second', () => {
    const fake = fakeClock();
    const { last, stop } = run(59_000, fake);
    expect(last().text).toBe('Code valid for 0:59');
    stop();
  });

  test('announces 1 minute left once, and expiry once', () => {
    const fake = fakeClock();
    const { snapshots, stop } = run(300_000, fake);
    fake.advance(300_000);
    const announcements = snapshots.map((s) => s.announcement).filter(Boolean);
    expect(announcements).toEqual([CODE_ONE_MINUTE_ANNOUNCEMENT, CODE_EXPIRED_TEXT]);
    stop();
  });

  test('does not announce before the one-minute mark', () => {
    const fake = fakeClock();
    const { snapshots, stop } = run(300_000, fake);
    fake.advance(239_000);
    expect(snapshots.some((s) => s.announcement === CODE_ONE_MINUTE_ANNOUNCEMENT)).toBe(false);
    stop();
  });

  test('transitions to expired at zero and stops ticking', () => {
    const fake = fakeClock();
    const { last, snapshots, stop } = run(300_000, fake);
    fake.advance(300_000);
    expect(last()).toEqual({
      remainingMs: 0,
      expired: true,
      text: CODE_EXPIRED_TEXT,
      announcement: CODE_EXPIRED_TEXT,
    });
    expect(fake.activeIntervals()).toBe(0);
    const count = snapshots.length;
    fake.advance(10_000);
    expect(snapshots.length).toBe(count);
    stop();
  });

  test('an already-expired deadline reports expiry immediately and starts no timer', () => {
    const fake = fakeClock();
    const { last, stop } = run(0, fake);
    expect(last().expired).toBe(true);
    expect(fake.activeIntervals()).toBe(0);
    stop();
  });

  test('stop clears the timer and silences later updates', () => {
    const fake = fakeClock();
    const { snapshots, stop } = run(300_000, fake);
    fake.advance(1_000);
    const count = snapshots.length;
    stop();
    expect(fake.activeIntervals()).toBe(0);
    fake.advance(10_000);
    expect(snapshots.length).toBe(count);
  });

  test('calling stop twice is safe', () => {
    const fake = fakeClock();
    const { stop } = run(300_000, fake);
    stop();
    expect(() => stop()).not.toThrow();
    expect(fake.activeIntervals()).toBe(0);
  });
});
