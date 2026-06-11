import { describe, expect, test } from 'bun:test';
import { delegateErrorResponse, validatePermissions } from '../routes/delegate-validation';

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
