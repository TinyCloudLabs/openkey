// Countdown for the CLI paste code on /delegate.
//
// The start value is the server's `expiresAt` minus the server's own `Date`
// response header, so the device clock never sets it. Every later tick is
// measured on the monotonic clock (performance.now()), so the displayed time
// does not move with wall-clock changes after receipt.

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
 * Remaining milliseconds until `expiresAt`, measured on the server's clock:
 * `expiresAt` minus the `Date` header of the same response. Returns null when
 * either value is missing or unparseable, or when the result is outside
 * (0, 6 minutes]. The caller then shows no countdown. The device clock is never read.
 */
export function remainingFromServerClock(expiresAt: string, serverDate: string | null): number | null {
  const expiryMs = Date.parse(expiresAt);
  const serverNowMs = serverDate === null ? NaN : Date.parse(serverDate);
  if (!Number.isFinite(expiryMs) || !Number.isFinite(serverNowMs)) return null;
  const remainingMs = expiryMs - serverNowMs;
  if (remainingMs <= 0 || remainingMs > 6 * 60_000) return null;
  return remainingMs;
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
