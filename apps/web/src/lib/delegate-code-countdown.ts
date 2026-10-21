// Countdown for the CLI paste code on /delegate.
//
// The server returns `expiresAt` as an absolute instant. The device clock is
// read once, when the response arrives, to turn that instant into a remaining
// duration. Every later tick is measured on the monotonic clock
// (performance.now()), so the displayed time does not move with wall-clock
// changes after receipt.

export const CODE_EXPIRED_TEXT = 'Code expired: start again in the CLI.';
export const CODE_ONE_MINUTE_ANNOUNCEMENT = '1 minute left to use this code.';

const ONE_MINUTE_MS = 60_000;
const TICK_MS = 250;

export type CodeCountdownSnapshot = {
  remainingMs: number;
  expired: boolean;
  text: string;
  /** Non-empty only on the tick that crosses 1:00 left or reaches expiry. */
  announcement: string;
};

export type CodeCountdownClock = {
  now(): number;
  setInterval(callback: () => void, ms: number): unknown;
  clearInterval(handle: unknown): void;
};

const browserClock: CodeCountdownClock = {
  now: () => performance.now(),
  setInterval: (callback, ms) => setInterval(callback, ms),
  clearInterval: (handle) => clearInterval(handle as number),
};

/** `m:ss`, rounded up to whole seconds so `0:00` is never shown while the code is still valid. */
export function formatCodeCountdown(remainingMs: number): string {
  if (!Number.isFinite(remainingMs) || remainingMs <= 0) return '0:00';
  const seconds = Math.ceil(remainingMs / 1000);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

/**
 * Remaining milliseconds until the server's `expiresAt`, read against the device
 * clock at `receivedAtMs`. Returns null for an unparseable instant, and 0 once
 * it has passed. This is the only reading that depends on the device clock.
 */
export function remainingFromExpiry(expiresAt: string, receivedAtMs: number = Date.now()): number | null {
  const expiryMs = Date.parse(expiresAt);
  if (!Number.isFinite(expiryMs)) return null;
  return Math.max(0, expiryMs - receivedAtMs);
}

/**
 * Ticks until `deadline` (a `clock.now()` value) and reports each tick.
 * Calls `onUpdate` once immediately, then every 250 ms; the expiry tick is the
 * last one and stops the timer. Returns an idempotent stop function.
 */
export function startCodeCountdown(options: {
  deadline: number;
  onUpdate: (snapshot: CodeCountdownSnapshot) => void;
  clock?: CodeCountdownClock;
}): () => void {
  const clock = options.clock ?? browserClock;
  let warned = false;
  let stopped = false;
  let handle: unknown = null;

  const stop = () => {
    stopped = true;
    if (handle !== null) clock.clearInterval(handle);
    handle = null;
  };

  const tick = () => {
    if (stopped) return;
    const remainingMs = Math.max(0, options.deadline - clock.now());
    const expired = remainingMs <= 0;
    let announcement = '';
    if (expired) {
      announcement = CODE_EXPIRED_TEXT;
    } else if (!warned && remainingMs <= ONE_MINUTE_MS) {
      warned = true;
      announcement = CODE_ONE_MINUTE_ANNOUNCEMENT;
    }
    options.onUpdate({
      remainingMs,
      expired,
      text: expired ? CODE_EXPIRED_TEXT : `Code valid for ${formatCodeCountdown(remainingMs)}`,
      announcement,
    });
    if (expired) stop();
  };

  tick();
  if (!stopped) handle = clock.setInterval(tick, TICK_MS);
  return stop;
}
