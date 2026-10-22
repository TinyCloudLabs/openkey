import { afterEach, describe, expect, test } from 'bun:test';
import {
  delegateErrorResponse,
  normalizeDelegateReason,
  signedSiweExpirationTime,
  validatePermissions,
} from '../routes/delegate-validation';

function invalidPermissionsPayload(permissions: unknown) {
  try {
    validatePermissions(permissions);
  } catch (err) {
    return delegateErrorResponse(err, 'Invalid permissions', 'invalid_permissions');
  }

  throw new Error('Expected permissions to be invalid');
}

describe('validatePermissions', () => {
  test('accepts fully qualified actions for short service names', () => {
    const permissions = validatePermissions([
      {
        service: 'kv',
        space: 'tinycloud:space:default',
        path: '',
        actions: ['tinycloud.kv/list'],
      },
    ]);

    expect(permissions).toEqual([
      {
        service: 'kv',
        space: 'tinycloud:space:default',
        path: '',
        actions: ['tinycloud.kv/list'],
      },
    ]);
  });

  test('rejects short actions with a field path and suggestion', () => {
    const payload = invalidPermissionsPayload([
      {
        service: 'tinycloud.kv',
        space: 'tinycloud:space:default',
        path: '',
        actions: ['list'],
      },
    ]);

    expect(payload.error).toBe('permissions[0].actions[0] must be fully qualified for service tinycloud.kv');
    expect(payload.code).toBe('invalid_permissions');
    expect(payload.message).toBe(payload.error);
    expect(payload.details).toEqual([
      {
        path: 'permissions[0].actions[0]',
        message: 'Action must start with tinycloud.kv/ and include an action name',
        value: 'list',
        expectedPrefix: 'tinycloud.kv/',
        suggestion: 'tinycloud.kv/list',
      },
    ]);
  });

  test('rejects actions that do not match the requested service', () => {
    const payload = invalidPermissionsPayload([
      {
        service: 'kv',
        space: 'tinycloud:space:default',
        path: '',
        actions: ['tinycloud.sql/read'],
      },
    ]);

    expect(payload.error).toBe('permissions[0].actions[0] must be fully qualified for service kv');
    expect(payload.code).toBe('invalid_permissions');
    expect(payload.details?.[0]?.path).toBe('permissions[0].actions[0]');
    expect(payload.details?.[0]?.value).toBe('tinycloud.sql/read');
    expect(payload.details?.[0]?.expectedPrefix).toBe('tinycloud.kv/');
    expect(payload.details?.[0]?.suggestion).toBeUndefined();
  });

  test('rejects empty action lists before prepareSession', () => {
    const payload = invalidPermissionsPayload([
      {
        service: 'kv',
        space: 'tinycloud:space:default',
        path: '',
        actions: [],
      },
    ]);

    expect(payload.error).toBe('permissions[0].actions must be a non-empty string[]');
    expect(payload.details).toEqual([
      {
        path: 'permissions[0].actions',
        message: 'Expected a non-empty array of action strings',
        expected: 'non-empty string[]',
      },
    ]);
  });
});

describe('validatePermissions held credentials (TC-1456 S5)', () => {
  const original = process.env.HELD_PRESENT_SIGNING_ENABLED;
  afterEach(() => {
    if (original === undefined) delete process.env.HELD_PRESENT_SIGNING_ENABLED;
    else process.env.HELD_PRESENT_SIGNING_ENABLED = original;
  });

  const credentialsEntry = [
    {
      service: 'credentials',
      space: 'tinycloud:space:default',
      path: 'mail',
      actions: ['tinycloud.credentials/present'],
    },
  ];

  test('refuses a credentials permission at validation when the flag is on', () => {
    process.env.HELD_PRESENT_SIGNING_ENABLED = 'true';
    const payload = invalidPermissionsPayload(credentialsEntry);
    expect(payload).toMatchObject({ error: expect.stringContaining('credentials cannot be delegated') });
  });

  test('refuses the tinycloud.credentials service spelling when the flag is on', () => {
    process.env.HELD_PRESENT_SIGNING_ENABLED = 'true';
    const payload = invalidPermissionsPayload([{ ...credentialsEntry[0], service: 'tinycloud.credentials' }]);
    expect(payload).toMatchObject({ error: expect.stringContaining('credentials cannot be delegated') });
  });

  test('does not apply the credentials denial when the flag is off', () => {
    delete process.env.HELD_PRESENT_SIGNING_ENABLED;
    expect(() => validatePermissions(credentialsEntry)).not.toThrow(/cannot be delegated/);
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
