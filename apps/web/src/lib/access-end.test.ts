// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { appKeyAccessStatement } from '../../../../packages/capability-review/src/index';
import { formatAccessEnd } from './access-end';

describe('the end of an access', () => {
  test('reads as a date and a time of day in UTC, with the zone written out', () => {
    expect(formatAccessEnd('2026-10-27T14:34:00.000Z')).toBe('Oct 27, 2026, 2:34 PM UTC');
    expect(formatAccessEnd('2026-11-24T00:05:59.999Z')).toBe('Nov 24, 2026, 12:05 AM UTC');
    expect(formatAccessEnd('2026-11-24T12:00:00.000Z')).toBe('Nov 24, 2026, 12:00 PM UTC');
  });

  test('does not depend on the zone of the machine', () => {
    const before = process.env.TZ;
    process.env.TZ = 'Asia/Tokyo';
    try {
      expect(formatAccessEnd('2026-10-27T14:34:00.000Z')).toBe('Oct 27, 2026, 2:34 PM UTC');
    } finally {
      if (before === undefined) delete process.env.TZ;
      else process.env.TZ = before;
    }
  });

  test('a value that is not a date is shown as it is', () => {
    expect(formatAccessEnd('soon')).toBe('soon');
  });

  test('the access line names the zone, and an unreadable end keeps its own line', () => {
    expect(appKeyAccessStatement('2026-10-27T14:34:00.000Z', formatAccessEnd)).toBe('This access lasts until Oct 27, 2026, 2:34 PM UTC.');
    expect(appKeyAccessStatement('soon', formatAccessEnd)).toBe('This access lasts until it expires.');
    expect(appKeyAccessStatement(null, formatAccessEnd)).toBe('This access lasts until it expires.');
  });
});
