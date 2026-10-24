// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { formatAccessEnd } from './access-end';

describe('the end of an access', () => {
  test('reads as a date and a time of day, not as the signed ISO string', () => {
    expect(formatAccessEnd('2026-11-24T14:00:00.000Z', 'en-GB', 'UTC')).toBe('24 Nov 2026, 14:00');
    expect(formatAccessEnd('2026-11-24T14:00:00.000Z', 'en-GB', 'Asia/Tokyo')).toBe('24 Nov 2026, 23:00');
  });

  test('a value that is not a date is shown as it is', () => {
    expect(formatAccessEnd('soon')).toBe('soon');
  });
});
