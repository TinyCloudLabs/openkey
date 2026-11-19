// @ts-expect-error bun:test is a runtime-only module; svelte-check does not ship its types.
import { describe, expect, test } from 'bun:test';
import { signingPreviewDeadline } from './signing-preview';

const serverNow = Date.parse('2026-11-08T00:00:00Z');
const serverDate = new Date(serverNow).toUTCString();
const expires = (ms: number) => new Date(serverNow + ms).toISOString();

describe('signing preview deadlines', () => {
  test('accounts for HTTP Date rounding and the entire request before enabling approval', () => {
    expect(signingPreviewDeadline(expires(5000), serverDate, 100, 600, 0)).toBe(4100);
  });

  test('server clock controls expiry despite device wall-clock skew', () => {
    const behind = signingPreviewDeadline(expires(5000), serverDate, 100, 600, serverNow - 86_400_000);
    const ahead = signingPreviewDeadline(expires(5000), serverDate, 100, 600, serverNow + 86_400_000);
    expect(behind).toBe(4100);
    expect(ahead).toBe(behind);
  });

  test('without Date, a slow device cannot extend the fixed API lifetime beyond request dispatch', () => {
    expect(signingPreviewDeadline(expires(300_000), null, 100, 600, serverNow - 86_400_000)).toBe(300_100);
  });

  test('without Date, the returned expiry can shorten the deadline', () => {
    expect(signingPreviewDeadline(expires(5000), null, 100, 600, serverNow)).toBe(5100);
  });

  test('refuses a deadline exhausted while the response was in flight', () => {
    expect(() => signingPreviewDeadline(expires(5000), serverDate, 100, 4100, serverNow)).toThrow();
  });

  test.each([undefined, null, '', 'not-a-date', 123])('refuses missing or malformed expiry %p', (value: unknown) => {
    expect(() => signingPreviewDeadline(value, serverDate, 100, 600, serverNow)).toThrow();
  });

  test('refuses an unreadable server Date rather than inventing a lifetime', () => {
    expect(() => signingPreviewDeadline(expires(5000), 'invalid', 100, 600, serverNow)).toThrow();
  });
});
