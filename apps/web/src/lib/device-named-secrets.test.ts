// @ts-expect-error bun:test is supplied by Bun, not the browser type environment.
import { expect, test } from 'bun:test';
import { devicePermissionSummary, type DevicePermission } from './device-authorization';

test('the device asks list labels each named secret and the current decrypt lifetime', () => {
  const permissions: DevicePermission[] = [
    { service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/FIRST_KEY', actions: ['tinycloud.kv/get'] },
    {
      service: 'tinycloud.kv', space: 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:secrets',
      path: 'vault/secrets/SECOND_KEY', actions: ['tinycloud.kv/list', 'tinycloud.kv/get', 'tinycloud.kv/put'],
    },
    { service: 'tinycloud.encryption', space: 'default', path: '', actions: ['tinycloud.encryption/decrypt'] },
  ];
  expect(permissions.map((permission) => devicePermissionSummary(permission, 1_800))).toEqual([
    'FIRST_KEY · Read', 'SECOND_KEY · Read, Write, List', 'Decrypt protected data for 30 minutes',
  ]);
  expect(devicePermissionSummary(permissions[2]!, 3_600)).toBe('Decrypt protected data for 1 hour');
  expect(devicePermissionSummary({ ...permissions[2]!, path: 'other' }, 3_600)).toBeNull();
});

test('the exact list prefix describes names only', () => {
  const list: DevicePermission = {
    service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/', actions: ['tinycloud.kv/list'],
  };
  expect(devicePermissionSummary(list, 3_600)).toBe('See the names of all your secrets (not their contents)');
  expect(devicePermissionSummary({ ...list, path: 'vault/secrets' }, 3_600)).toBeNull();
  expect(devicePermissionSummary({ ...list, actions: [...list.actions, 'tinycloud.kv/get'] }, 3_600)).toBeNull();
});
