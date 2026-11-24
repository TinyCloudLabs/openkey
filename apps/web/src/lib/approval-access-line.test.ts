// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { accessLastsLine, remainingAccessMs } from './approval-expiry';

const S = 1000;
const M = 60 * S;
const H = 60 * M;
const D = 24 * H;
const NOW = Date.UTC(2026, 10, 17, 12, 0, 0);
const at = (ms: number) => new Date(NOW + ms).toISOString();

describe('remainingAccessMs: how long a message signed as written lasts', () => {
  test('runs to the Expiration Time', () => {
    expect(remainingAccessMs(at(7 * D), NOW)).toBe(7 * D);
    expect(remainingAccessMs(at(2 * H), NOW)).toBe(2 * H);
  });

  test('a few seconds either way snap to the whole unit', () => {
    expect(remainingAccessMs(at(7 * D - 3 * S), NOW)).toBe(7 * D);
    expect(remainingAccessMs(at(H + 4 * S), NOW)).toBe(H);
  });

  test('otherwise it rounds up to the minute, never showing less than is granted', () => {
    expect(remainingAccessMs(at(89 * M + 50 * S), NOW)).toBe(90 * M);
    expect(remainingAccessMs(at(45 * S), NOW)).toBe(M);
  });

  test('no end, an unreadable end or one that has passed has no length', () => {
    expect(remainingAccessMs(null, NOW)).toBeNull();
    expect(remainingAccessMs('', NOW)).toBeNull();
    expect(remainingAccessMs('not a date', NOW)).toBeNull();
    expect(remainingAccessMs(at(0), NOW)).toBeNull();
    expect(remainingAccessMs(at(-H), NOW)).toBeNull();
  });
});

describe('accessLastsLine', () => {
  test('names who holds the access and how long it lasts', () => {
    expect(accessLastsLine('app', 2 * H, NOW)).toBe("This app's access to your data lasts 2 hours.");
    expect(accessLastsLine('device', 30 * M, NOW)).toBe("This device's access to your data lasts 30 minutes.");
  });

  test('over two days it names the day it ends', () => {
    expect(accessLastsLine('app', 30 * D, NOW)).toMatch(/^This app's access to your data lasts 30 days, until [A-Z][a-z]{2} \d{1,2}\.$/);
  });
});
