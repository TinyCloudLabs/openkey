// TC-2322: "Welcome to OpenKey" is for the first session of a brand-new account. The server stamps the user and its
// first session in the same request, so the two timestamps are seconds apart only for that session; a later sign-in
// of an older account is far from the user's creation. Only server timestamps are compared against each other (no
// client/server clock skew); the client clock only bounds how long the welcome can show.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { isFirstSession } from './first-session';

const NOW = Date.parse('2026-11-02T05:00:00.000Z');
const at = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();
const MIN = 60_000;

describe('isFirstSession', () => {
  test('a session created in the same request as its user is the first session', () => {
    expect(isFirstSession({ session: { createdAt: at(-5_000) }, user: { createdAt: at(-5_400) } }, NOW)).toBe(true);
  });

  test('a later sign-in of an older account is not', () => {
    expect(isFirstSession({ session: { createdAt: at(-5_000) }, user: { createdAt: at(-30 * 24 * 60 * MIN) } }, NOW)).toBe(false);
  });

  test('the welcome ends with the first half hour of that session, even though the two stamps still agree', () => {
    const first = { session: { createdAt: at(-29 * MIN) }, user: { createdAt: at(-29 * MIN - 400) } };
    const later = { session: { createdAt: at(-31 * MIN) }, user: { createdAt: at(-31 * MIN - 400) } };
    expect(isFirstSession(first, NOW)).toBe(true);
    expect(isFirstSession(later, NOW)).toBe(false);
  });

  test('an unreadable or missing timestamp is never a welcome', () => {
    expect(isFirstSession(null, NOW)).toBe(false);
    expect(isFirstSession({}, NOW)).toBe(false);
    expect(isFirstSession({ session: { createdAt: at(-1_000) } }, NOW)).toBe(false);
    expect(isFirstSession({ session: { createdAt: 'soon' }, user: { createdAt: at(-1_000) } }, NOW)).toBe(false);
  });
});
