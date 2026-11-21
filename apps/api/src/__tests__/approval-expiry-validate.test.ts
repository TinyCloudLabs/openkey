// TC-2272: which chosen expiries the server will write into a message it signs.
import { describe, expect, test } from 'bun:test';
import { MIN_EXPIRATION_LEAD_MS, validateExpirationOverride, withExpirationTime, expirationTimeOf, delegationCeilingMs, assertWithinDelegationCeiling } from '../services/approval-expiry';

const now = Date.UTC(2026, 9, 31, 12);
const iso = (offsetMs: number) => new Date(now + offsetMs).toISOString();
const siwe = { issuedAt: iso(-1000) };

describe('validateExpirationOverride', () => {
  test('caps chosen expiry at ten calendar years from the injected clock', () => {
    const ceiling = delegationCeilingMs(now);
    expect(new Date(ceiling).toISOString()).toBe('2036-10-31T12:00:00.000Z');
    expect(validateExpirationOverride(iso(61_000), siwe, MIN_EXPIRATION_LEAD_MS, now).ok).toBe(true);
    const within = new Date(ceiling - 86_400_000).toISOString();
    const beyond = new Date(ceiling + 86_400_000).toISOString();
    expect(validateExpirationOverride(within, siwe, MIN_EXPIRATION_LEAD_MS, now).ok).toBe(true);
    expect(validateExpirationOverride(beyond, siwe, MIN_EXPIRATION_LEAD_MS, now)).toEqual({ ok: false, reason: 'too_long' });
    expect(validateExpirationOverride('9999-12-31T23:59:59.000Z', siwe, MIN_EXPIRATION_LEAD_MS, now)).toEqual({ ok: false, reason: 'too_long' });
  });
});

describe('assertWithinDelegationCeiling', () => {
  const delegation = `example.com wants you to sign in with your Ethereum account:
0x0000000000000000000000000000000000000000

Example statement

URI: https://example.com
Version: 1
Chain ID: 1
Nonce: abcdefgh
Issued At: 2026-10-31T12:00:00.000Z
Resources:
- urn:recap:foo`;
  test('requires a positional expiry only for TinyCloud delegation ReCap SIWEs', () => {
    expect(assertWithinDelegationCeiling(delegation, now)).toBe('missing');
    const within = withExpirationTime(delegation, new Date(delegationCeilingMs(now) - 86_400_000).toISOString())!;
    expect(assertWithinDelegationCeiling(within, now)).toBe('ok');
    const tooLong = withExpirationTime(delegation, new Date(delegationCeilingMs(now) + 86_400_000).toISOString())!;
    expect(assertWithinDelegationCeiling(tooLong, now)).toBe('too_long');
    expect(assertWithinDelegationCeiling('ordinary sign-in SIWE', now)).toBe('ok');
    expect(assertWithinDelegationCeiling('plain message', now)).toBe('ok');
    expect(assertWithinDelegationCeiling('plain text\n- urn:recap:foo', now)).toBe('ok');
  });
  test.each(['\r', '\u2028', '\u2029', '\u0085'])('does not parse statement line separator %p as an expiry', (separator) => {
    const spoof = delegation.replace('Example statement', `Expiration Time: 2027-01-01T00:00:00Z${separator}Example statement`);
    expect(assertWithinDelegationCeiling(spoof, now)).toBe('missing');
    const long = withExpirationTime(delegation, '9999-12-31T23:59:59.000Z')!;
    expect(assertWithinDelegationCeiling(long.replace('Example statement', `Expiration Time: 2027-01-01T00:00:00Z${separator}Example statement`), now)).toBe('too_long');
  });
  test('clamps leap-day ceilings and handles CRLF as malformed', () => {
    const leapDay = Date.UTC(2028, 1, 29, 12);
    expect(new Date(delegationCeilingMs(leapDay)).toISOString()).toBe('2038-02-28T12:00:00.000Z');
    const crlf = withExpirationTime(delegation, '2030-01-01T00:00:00.000Z')!.replaceAll('\n', '\r\n');
    expect(assertWithinDelegationCeiling(crlf, now)).toBe('malformed');
    expect(expirationTimeOf(crlf)).toBeUndefined();
  });
  test('does not read Expiration Time text in a multi-line statement as the header', () => {
    const statement = delegation.replace('Example statement', 'Example\nExpiration Time: 2027-01-01T00:00:00Z');
    expect(assertWithinDelegationCeiling(statement, now)).toBe('malformed');
    expect(expirationTimeOf(statement)).toBeUndefined();
    expect(withExpirationTime(statement, '2030-01-01T00:00:00.000Z')).toBeNull();
  });
});

describe('validateExpirationOverride bounds', () => {
  test('enforces the lower lead time and Issued At / Not Before bounds', () => {
    expect(validateExpirationOverride(iso(30_000), siwe, MIN_EXPIRATION_LEAD_MS, now).ok).toBe(false);
    expect(validateExpirationOverride(iso(30_000), siwe, 0, now).ok).toBe(true);
    expect(validateExpirationOverride(iso(0), siwe, 0, now).ok).toBe(false);
    expect(validateExpirationOverride(iso(5_000), { issuedAt: iso(5_000) }, 0, now).ok).toBe(false);
    expect(validateExpirationOverride(iso(5_000), { issuedAt: iso(-1000), notBefore: iso(5_000) }, 0, now).ok).toBe(false);
    expect(validateExpirationOverride(iso(5_001), { issuedAt: iso(-1000), notBefore: iso(5_000) }, 0, now).ok).toBe(true);
  });
  test.each([null, 5, {}, 'soon', '2030-01-01', '2030-01-01T00:00:00Z', '10000-01-01T00:00:00.000Z', '+010000-01-01T00:00:00.000Z'])('refuses %p', (value) => {
    expect(validateExpirationOverride(value, siwe, 0, now).ok).toBe(false);
  });
});

describe('withExpirationTime', () => {
  test('replaces a positional line or inserts it after Issued At, never in statement text', () => {
    const message = `example.com wants you to sign in with your Ethereum account:
0x0000000000000000000000000000000000000000

Example

URI: https://example.com
Version: 1
Chain ID: 1
Nonce: abcdefgh
Issued At: 2026-10-31T12:00:00.000Z
Expiration Time: 2026-01-01T00:00:00.000Z
Resources:
- urn:recap:foo`;
    expect(withExpirationTime(message, '2030-01-01T00:00:00.000Z')).toBe(message.replace('2026-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'));
    expect(withExpirationTime('a\nb', '2030-01-01T00:00:00.000Z')).toBeNull();
    expect(withExpirationTime(`${message}\nExpiration Time: 2027-01-01T00:00:00.000Z`, '2030-01-01T00:00:00.000Z')).toBe(`${message.replace('2026-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z')}\nExpiration Time: 2027-01-01T00:00:00.000Z`);
  });
});
