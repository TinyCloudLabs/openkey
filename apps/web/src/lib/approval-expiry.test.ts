// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  EXPIRY_PRESETS,
  LONG_EXPIRY_MS,
  LONG_EXPIRY_WARNING,
  expiryAt,
  formatExpiry,
  parseExpiry,
  requestedExpiryMs,
} from './approval-expiry';

const S = 1000;
const M = 60 * S;
const H = 60 * M;
const D = 24 * H;

describe('parseExpiry', () => {
  test.each([
    ['5600s', 5600 * S],
    ['90m', 90 * M],
    ['1h', H],
    ['40d', 40 * D],
    ['2w', 14 * D],
    ['1y', 365 * D],
  ])('%s', (text: string, ms: number) => {
    expect(parseExpiry(text)).toEqual({ ok: true, ms });
  });

  test('units are case-insensitive and surrounding space is ignored', () => {
    expect(parseExpiry('  40D ')).toEqual({ ok: true, ms: 40 * D });
    expect(parseExpiry('1Y')).toEqual({ ok: true, ms: 365 * D });
    expect(parseExpiry('7 d')).toEqual({ ok: true, ms: 7 * D });
  });

  test.each(['', '   ', 'abc', '5', 'd', '1.5h', '1,5h', '-1d', '+1d', '0d', '000s', '5x', '1d2h', '1 day', '١d', '1e3s'])(
    'refuses %p with a plain message',
    (text: string) => {
      const result = parseExpiry(text);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.message.length).toBeGreaterThan(0);
    },
  );

  test('zero and negative get their own message', () => {
    const zero = parseExpiry('0d');
    const negative = parseExpiry('-5d');
    expect(zero.ok || zero.message).toBe('Enter a time longer than zero.');
    expect(negative.ok || negative.message).toBe('Enter a time longer than zero.');
  });

  test('an absurd value is refused without integer overflow', () => {
    for (const text of ['99999999999999999999999y', '9007199254740993d', '300000y', '9999999999999999s']) {
      const result = parseExpiry(text);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.message).toBe('That is too far in the future.');
    }
  });

  test('the last representable year is accepted, one past it is refused', () => {
    const now = Date.UTC(2026, 9, 31);
    const max = Date.UTC(9999, 11, 31, 23, 59, 59);
    const ok = parseExpiry(`${Math.floor((max - now) / S)}s`, now);
    expect(ok.ok).toBe(true);
    const over = parseExpiry(`${Math.floor((max - now) / S) + 2}s`, now);
    expect(over.ok).toBe(false);
  });
});

describe('formatExpiry', () => {
  test.each([
    [7 * D, '7d'],
    [30 * D, '30d'],
    [24 * H, '1d'],
    [H, '1h'],
    [90 * M, '90m'],
    [5600 * S, '5600s'],
    [365 * D, '1y'],
    [730 * D, '2y'],
  ])('%d ms -> %s', (ms: number, label: string) => {
    expect(formatExpiry(ms)).toBe(label);
  });

  test('round trips through parseExpiry', () => {
    for (const ms of [5600 * S, 90 * M, 40 * D, 365 * D, 3 * H]) {
      expect(parseExpiry(formatExpiry(ms))).toEqual({ ok: true, ms });
    }
  });
});

describe('requestedExpiryMs', () => {
  test('is the span the app asked for, rounded to the nearest second', () => {
    expect(requestedExpiryMs('2026-10-31T00:00:00.000Z', '2026-11-07T00:00:00.000Z')).toBe(7 * D);
    expect(requestedExpiryMs('2026-10-31T00:00:00.400Z', '2026-11-07T00:00:00.000Z')).toBe(7 * D);
  });

  test('absorbs a few seconds of clock skew so a 7d request reads 7d', () => {
    expect(formatExpiry(requestedExpiryMs('2026-10-31T00:00:03.000Z', '2026-11-07T00:00:00.000Z')!)).toBe('7d');
    expect(formatExpiry(requestedExpiryMs('2026-10-31T00:00:00.000Z', '2026-11-07T00:00:02.000Z')!)).toBe('7d');
  });

  test('is null when either time is missing or the span is not positive', () => {
    expect(requestedExpiryMs(undefined, '2026-11-07T00:00:00.000Z')).toBeNull();
    expect(requestedExpiryMs('2026-10-31T00:00:00.000Z', 'nope')).toBeNull();
    expect(requestedExpiryMs('2026-11-07T00:00:00.000Z', '2026-10-31T00:00:00.000Z')).toBeNull();
  });
});

describe('presets, warning and expiry time', () => {
  test('presets are 1 hr, 24 hr, 7d, 30d', () => {
    expect(EXPIRY_PRESETS).toEqual([
      { label: '1 hr', ms: H },
      { label: '24 hr', ms: 24 * H },
      { label: '7d', ms: 7 * D },
      { label: '30d', ms: 30 * D },
    ]);
  });

  test('the warning threshold is more than one year', () => {
    expect(LONG_EXPIRY_MS).toBe(365 * D);
    expect(LONG_EXPIRY_WARNING).toBe("That's a long time. OpenKey can't cancel it early once you approve.");
  });

  test('expiryAt adds the duration to now, as an ISO string', () => {
    expect(expiryAt(7 * D, Date.UTC(2026, 9, 31))).toBe('2026-11-07T00:00:00.000Z');
  });
});

describe('expiryLimitNote', () => {
  test('names the longest time the request allows and how to get longer', async () => {
    const { expiryLimitNote } = await import('./approval-expiry');
    expect(expiryLimitNote(7 * D)).toBe(
      'This app asked for up to 7d. To allow longer, start the request again with a longer expiry.',
    );
  });
});

describe('the one-minute floor', () => {
  test.each(['1s', '30s', '59s'])('%s is refused', (text: string) => {
    const result = parseExpiry(text);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.message).toBe('Use at least 1m.');
  });
  test('60s and 1m are accepted', () => {
    expect(parseExpiry('60s')).toEqual({ ok: true, ms: 60 * S });
    expect(parseExpiry('1m')).toEqual({ ok: true, ms: 60 * S });
  });
});
