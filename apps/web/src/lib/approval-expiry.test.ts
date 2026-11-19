// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  LONG_EXPIRY_MS,
  LONG_EXPIRY_WARNING,
  ONCE_DEFAULT_EXPIRY_MS,
  expiryAt,
  daysOverTwoDays,
  formatDuration,
  formatDurationWithEnd,
  formatExpiry,
  onceDefaultExpiryMs,
  parseExpiry,
  requestedExpiryMs,
  approvalRequestStartSeconds,
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
  test('the warning threshold is more than one year', () => {
    expect(LONG_EXPIRY_MS).toBe(365 * D);
    expect(LONG_EXPIRY_WARNING).toBe("That's a long time. OpenKey can't cancel it early once you approve.");
  });

  test('expiryAt adds the duration to now, as an ISO string', () => {
    expect(expiryAt(7 * D, Date.UTC(2026, 9, 31))).toBe('2026-11-07T00:00:00.000Z');
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

describe('expiryAtCapped', () => {
  const now = Date.UTC(2026, 9, 31);
  test('is now plus the duration, but never past the time the requester asked for', async () => {
    const { expiryAtCapped } = await import('./approval-expiry');
    expect(expiryAtCapped(H, '2026-11-07T00:00:00.000Z', now)).toBe('2026-10-31T01:00:00.000Z');
    expect(expiryAtCapped(7 * D, '2026-11-05T00:00:00.000Z', now)).toBe('2026-11-05T00:00:00.000Z');
    expect(expiryAtCapped(H, null, now)).toBe('2026-10-31T01:00:00.000Z');
    expect(expiryAtCapped(H, 'not a time', now)).toBe('2026-10-31T01:00:00.000Z');
  });
});

describe('onceDefaultExpiryMs (TC-3111)', () => {
  test('a one-time request that asks for more than an hour starts at one hour', () => {
    expect(ONCE_DEFAULT_EXPIRY_MS).toBe(H);
    expect(onceDefaultExpiryMs(true, H + S)).toBe(H);
    expect(onceDefaultExpiryMs(true, 7 * D)).toBe(H);
  });

  test('an hour or less, an unknown request, or a request that is not one-time keeps what the app asked for', () => {
    expect(onceDefaultExpiryMs(true, H)).toBeNull();
    expect(onceDefaultExpiryMs(true, 30 * M)).toBeNull();
    expect(onceDefaultExpiryMs(true, null)).toBeNull();
    expect(onceDefaultExpiryMs(false, 7 * D)).toBeNull();
  });
});

describe('approvalRequestStartSeconds', () => {
  test('a request that suggests nothing starts at one hour, however long its signed maximum', () => {
    expect(approvalRequestStartSeconds(7 * 86_400)).toBe(3600);
    expect(approvalRequestStartSeconds(8000 * 365 * 86_400)).toBe(3600);
    expect(approvalRequestStartSeconds(7 * 86_400, 0)).toBe(3600);
  });
  test('a request for less than an hour starts at what it asked for', () => {
    expect(approvalRequestStartSeconds(600)).toBe(600);
    expect(approvalRequestStartSeconds(7 * 86_400, 1800)).toBe(1800);
  });
  test('a suggestion above an hour is not used as the start, and one above the maximum is ignored', () => {
    expect(approvalRequestStartSeconds(30 * 86_400, 7 * 86_400)).toBe(3600);
    expect(approvalRequestStartSeconds(7200, 30 * 86_400)).toBe(3600);
    expect(approvalRequestStartSeconds(900, 30 * 86_400)).toBe(900);
  });
});

describe('formatDuration over two days', () => {
  const over: Array<[number, string]> = [
    [700 * H, '30 days'],
    [745 * H, '32 days'],
    [720 * H, '30 days'],
    [49 * H, '3 days'],
    [3 * D, '3 days'],
    [(30 * D) + (5 * H) + (7 * M), '31 days'],
    [400 * D, '400 days'],
    [365 * D, '1 year'],
    [730 * D, '2 years'],
  ];
  for (const [ms, label] of over) {
    test(`${ms} ms reads as ${label}`, () => {
      expect(formatDuration(ms)).toBe(label);
    });
  }

  const within: Array<[number, string]> = [
    [47 * H, '47 hours'],
    [36 * H, '36 hours'],
    [90 * M, '90 minutes'],
    [H, '1 hour'],
    [45 * S, '45 seconds'],
  ];
  for (const [ms, label] of within) {
    test(`${ms} ms, two days or less, keeps its smaller unit: ${label}`, () => {
      expect(formatDuration(ms)).toBe(label);
    });
  }

  test('no duration over two days is ever worded in hours', () => {
    for (let hours = 49; hours <= 24 * 400; hours += 7) {
      expect(formatDuration(hours * H)).not.toMatch(/hour|minute|second/);
    }
  });

  test('the days shown never cover less time than the grant', () => {
    for (let minutes = 2 * 24 * 60 + 1; minutes <= 400 * 24 * 60; minutes += 977) {
      const ms = minutes * M;
      expect(daysOverTwoDays(ms)! * D).toBeGreaterThanOrEqual(ms);
    }
  });

  test('daysOverTwoDays is null for two days or less and rounds the rest up', () => {
    expect(daysOverTwoDays(2 * D)).toBeNull();
    expect(daysOverTwoDays(2 * D + 1)).toBe(3);
    expect(daysOverTwoDays(700 * H)).toBe(30);
  });
});

describe('formatDurationWithEnd', () => {
  const now = Date.UTC(2026, 10, 18, 4, 30);

  test('over two days names the length and the day it ends, month first', () => {
    expect(formatDurationWithEnd(30 * D, now, 'UTC')).toBe('30 days, on Dec 18');
    expect(formatDurationWithEnd(700 * H, now, 'UTC')).toBe('30 days, on Dec 17');
  });

  test('the day follows the instant, not the rounded days', () => {
    // 23:30 UTC plus 30 days is still the 18th; plus 30 days 1 hour is the 19th.
    const late = Date.UTC(2026, 10, 18, 23, 30);
    expect(formatDurationWithEnd(30 * D, late, 'UTC')).toBe('30 days, on Dec 18');
    expect(formatDurationWithEnd(30 * D + H, late, 'UTC')).toBe('31 days, on Dec 19');
  });

  test('the day is the owner\'s own, not the UTC one', () => {
    // The window ends Dec 18 02:00 UTC: still the evening of Dec 17 in New York, already Dec 18 afternoon in Tokyo.
    const start = Date.UTC(2026, 10, 18, 2, 0);
    expect(formatDurationWithEnd(30 * D, start, 'UTC')).toBe('30 days, on Dec 18');
    expect(formatDurationWithEnd(30 * D, start, 'America/New_York')).toBe('30 days, on Dec 17');
    expect(formatDurationWithEnd(30 * D, start, 'Asia/Tokyo')).toBe('30 days, on Dec 18');
    expect(formatDurationWithEnd(30 * D, Date.UTC(2026, 10, 17, 20, 0), 'Asia/Tokyo')).toBe('30 days, on Dec 18');
  });

  test('a day in another year carries the year', () => {
    expect(formatDurationWithEnd(60 * D, now, 'UTC')).toBe('60 days, on Jan 17, 2027');
    expect(formatDurationWithEnd(365 * D, now, 'UTC')).toBe('1 year, on Nov 18, 2027');
  });

  test('two days or less has no date', () => {
    expect(formatDurationWithEnd(36 * H, now, 'UTC')).toBe('36 hours');
    expect(formatDurationWithEnd(H, now, 'UTC')).toBe('1 hour');
  });
});
