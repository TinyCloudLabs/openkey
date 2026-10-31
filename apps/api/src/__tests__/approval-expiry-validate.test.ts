// TC-2272: which chosen expiries the server will write into a message it signs.
import { describe, expect, test } from 'bun:test';
import { MIN_EXPIRATION_LEAD_MS, validateExpirationOverride, withExpirationTime } from '../services/approval-expiry';

const now = Date.UTC(2026, 9, 31, 12);
const iso = (offsetMs: number) => new Date(now + offsetMs).toISOString();
const siwe = { issuedAt: iso(-1000) };

describe('validateExpirationOverride', () => {
  test('accepts a time a minute or more ahead, with no upper limit', () => {
    expect(validateExpirationOverride(iso(61_000), siwe, MIN_EXPIRATION_LEAD_MS, now).ok).toBe(true);
    expect(validateExpirationOverride('9999-12-31T23:59:59.000Z', siwe, MIN_EXPIRATION_LEAD_MS, now).ok).toBe(true);
  });
  test('refuses under the floor at preview, accepts it at sign time while still in the future', () => {
    expect(validateExpirationOverride(iso(30_000), siwe, MIN_EXPIRATION_LEAD_MS, now).ok).toBe(false);
    expect(validateExpirationOverride(iso(30_000), siwe, 0, now).ok).toBe(true);
    expect(validateExpirationOverride(iso(0), siwe, 0, now).ok).toBe(false);
  });
  test('refuses a time at or before Issued At or Not Before', () => {
    expect(validateExpirationOverride(iso(5_000), { issuedAt: iso(5_000) }, 0, now).ok).toBe(false);
    expect(validateExpirationOverride(iso(5_000), { issuedAt: iso(-1000), notBefore: iso(5_000) }, 0, now).ok).toBe(false);
    expect(validateExpirationOverride(iso(5_001), { issuedAt: iso(-1000), notBefore: iso(5_000) }, 0, now).ok).toBe(true);
  });
  test.each([null, 5, {}, 'soon', '2030-01-01', '2030-01-01T00:00:00Z', '10000-01-01T00:00:00.000Z'])('refuses %p', (value) => {
    expect(validateExpirationOverride(value, siwe, 0, now).ok).toBe(false);
  });
});

describe('withExpirationTime', () => {
  test('replaces the one line and nothing else; refuses zero or two', () => {
    const message = 'a\nIssued At: x\nExpiration Time: 2026-01-01T00:00:00.000Z\nResources:\n- r';
    expect(withExpirationTime(message, '2030-01-01T00:00:00.000Z')).toBe(message.replace('2026-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'));
    expect(withExpirationTime('a\nb', '2030-01-01T00:00:00.000Z')).toBeNull();
    expect(withExpirationTime(`${message}\nExpiration Time: 2027-01-01T00:00:00.000Z`, '2030-01-01T00:00:00.000Z')).toBeNull();
  });
});
