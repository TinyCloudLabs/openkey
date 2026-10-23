import { describe, expect, test } from 'bun:test';
import { validatePermissions } from '../routes/delegate-session';
import {
  delegateErrorResponse,
  normalizeDelegateReason,
  signedSiweExpirationTime,
} from '../routes/delegate-validation';

const base = { service: 'kv', space: 'tinycloud:space:default', path: '', actions: ['tinycloud.kv/list'] };

function refusalFor(permissions: unknown) {
  try {
    validatePermissions(permissions);
  } catch (err) {
    return delegateErrorResponse(err, 'Invalid permissions', 'invalid_permissions');
  }

  throw new Error('Expected permissions to be refused');
}

describe('validatePermissions', () => {
  test('accepts an entry with no narrowing fields and drops unknown fields', () => {
    const result = validatePermissions([{ ...base, skipPrefix: true, description: 'note' }]);

    expect(result).toEqual([base]);
    expect(Object.keys(result[0] ?? {})).not.toContain('skipPrefix');
    expect(Object.keys(result[0] ?? {})).not.toContain('description');
  });

  test('accepts caveats that restrict nothing', () => {
    expect(validatePermissions([{ ...base, caveats: [] }])).toEqual([base]);
    expect(validatePermissions([{ ...base, caveats: [{}] }])).toEqual([base]);
    expect(validatePermissions([{ ...base, caveats: undefined }])).toEqual([base]);
  });

  test.each<[string, unknown]>([
    ['non-empty array', [{ maxSize: 10 }]],
    ['string', 'x'],
    ['number', 1],
    ['null', null],
    ['object', {}],
    ['array of non-objects', [1]],
  ])('refuses caveats given as %s', (_label, caveats) => {
    const payload = refusalFor([{ ...base, caveats }]);

    expect(payload.code).toBe('invalid_permissions');
    expect(payload.error).toContain('permissions[0]');
    expect(payload.error).toContain('caveats');
  });

  test.each<[string, Record<string, unknown>]>([
    ['expiry', { expiry: 1700000000 }],
    ['expiryMs', { expiryMs: 1700000000000 }],
    ['expiry null', { expiry: null }],
    ['expiryMs null', { expiryMs: null }],
  ])('refuses per-entry %s', (_label, extra) => {
    const payload = refusalFor([{ ...base, ...extra }]);

    expect(payload.code).toBe('invalid_permissions');
    expect(payload.error).toContain('permissions[0]');
    expect(payload.error).toContain(`(${Object.keys(extra)[0]})`);
  });

  test('refusal messages never contain the offending value', () => {
    const payload = refusalFor([{ ...base, expiryMs: 1700000000000 }]);

    expect(payload.error).not.toContain('1700000000000');
  });

  test('refuses the whole request when any entry carries a refused field', () => {
    expect(() => validatePermissions([base, { ...base, expiryMs: 5 }])).toThrow();
    expect(() => validatePermissions([base, { ...base, caveats: [{ maxSize: 1 }] }])).toThrow();
  });
});

describe('normalizeDelegateReason', () => {
  test('accepts optional caller context and trims whitespace', () => {
    expect(normalizeDelegateReason('  Allow CLI access\nfor a deploy.  ')).toBe('Allow CLI access for a deploy.');
  });

  test('omits blank or non-string reasons', () => {
    expect(normalizeDelegateReason('   ')).toBeUndefined();
    expect(normalizeDelegateReason({ reason: 'nope' })).toBeUndefined();
  });
});

describe('signedSiweExpirationTime', () => {
  test('reads the SIWE Expiration Time', () => {
    const expirationTime = '2026-07-01T00:00:00.000Z';
    const siwe = [
      'cli.tinycloud.xyz wants you to sign in',
      '',
      `Expiration Time: ${expirationTime}`,
    ].join('\n');

    expect(signedSiweExpirationTime(siwe)).toBe(expirationTime);
  });

  test('rejects missing or invalid expiry values', () => {
    expect(signedSiweExpirationTime(undefined)).toBeUndefined();
    expect(signedSiweExpirationTime('no expiry here')).toBeUndefined();
    expect(signedSiweExpirationTime('Expiration Time: not-a-date')).toBeUndefined();
  });
});
