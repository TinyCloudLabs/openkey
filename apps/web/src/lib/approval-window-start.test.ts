import { describe, expect, test } from 'bun:test';
import { expiryAt, formatDurationWithEnd, windowStartMs } from './approval-expiry';

const D = 86_400_000;

describe('the end day on the face is counted from the request\'s Issued At', () => {
  test('windowStartMs reads Issued At, never later than now, and falls back to now', () => {
    const later = Date.UTC(2026, 10, 19);
    expect(windowStartMs('2026-11-18T23:59:50.000Z', later)).toBe(Date.UTC(2026, 10, 18, 23, 59, 50));
    expect(windowStartMs('2026-11-20T00:00:00.000Z', later)).toBe(later);
    expect(windowStartMs(undefined, 5)).toBe(5);
    expect(windowStartMs('soon', 5)).toBe(5);
  });

  test('a request issued just before midnight names the day its Issued At + length falls on, not the later preview time', () => {
    const issued = Date.UTC(2026, 10, 18, 23, 59, 50);
    // Previewed 20 s later (next UTC day): counting from the preview would name Dec 19.
    expect(formatDurationWithEnd(30 * D, issued, 'UTC')).toBe('30 days, until Dec 18');
    expect(new Date(expiryAt(30 * D, issued)).toISOString()).toBe('2026-12-18T23:59:50.000Z');
  });
});
