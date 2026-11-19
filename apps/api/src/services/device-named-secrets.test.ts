import { expect, test } from 'bun:test';
import { deviceRequestPermissions, type DevicePermission } from './device-authorization';

const named: DevicePermission = {
  service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/APP_TOKEN',
  actions: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/list'],
};
const decrypt: DevicePermission = {
  service: 'tinycloud.encryption', space: 'default', path: '', actions: ['tinycloud.encryption/decrypt'],
};
const capabilities: DevicePermission = {
  service: 'tinycloud.capabilities', space: 'secrets', path: '', actions: ['tinycloud.capabilities/read'],
};

test('accepts separate named secrets and the default decrypt entry in either order', () => {
  for (const space of [named.space, 'tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:secrets']) {
    const secrets = [
      { ...capabilities, space },
      { ...named, space },
      { ...named, space, path: `vault/secrets/${'A'.repeat(64)}` },
    ];
    expect(deviceRequestPermissions(secrets)).toEqual(secrets);
    for (const permissions of [[decrypt, ...secrets], [...secrets, decrypt]]) {
      expect(deviceRequestPermissions(permissions)).toEqual(permissions);
    }
  }
});

test.each([
  '', 'vault/', 'vault/APP_TOKEN', 'vault/secrets', 'vault/secrets/', 'secrets/APP_TOKEN',
  'vault/secrets/.', 'vault/secrets/..', 'vault/secrets/APP_TOKEN/', 'vault/secrets/A/B',
  'vault/secrets/scoped/app/APP_TOKEN', 'vault/secrets/*', 'vault/secrets/A*', 'vault/secrets/%41',
  'vault/secrets/token', 'vault/secrets/0VALUE', 'vault/secrets/APP-TOKEN', 'vault/secrets/A\n',
  `vault/secrets/${'A'.repeat(65)}`,
])('refuses secret path %j', (path) => {
  expect(() => deviceRequestPermissions([{ ...named, path }])).toThrow(/one named secret/);
});

test.each(['tinycloud.kv/metadata', 'tinycloud.kv/del', 'tinycloud.kv/*', 'get', 'tinycloud.sql/read'])(
  'refuses %s on a named secret',
  (ability) => {
    expect(() => deviceRequestPermissions([{ ...named, actions: [...named.actions, ability] }])).toThrow(/ability/);
  },
);

test.each(['tinycloud.sql', 'tinycloud.delegation', 'tinycloud.hooks'])(
  'refuses %s in the secrets space',
  (service) => {
    expect(() => deviceRequestPermissions([{ ...named, service }])).toThrow(/device authorization/);
  },
);

test('requires exactly capabilities/read at the root beside named KV entries', () => {
  expect(() => deviceRequestPermissions([named])).toThrow(/must include tinycloud.capabilities\/read/);
  expect(() => deviceRequestPermissions([capabilities, decrypt])).toThrow(/at least one named secret/);
  expect(() => deviceRequestPermissions([named, { ...capabilities, path: named.path }])).toThrow(/must be empty/);
  expect(() => deviceRequestPermissions([named, { ...capabilities, actions: ['tinycloud.capabilities/write'] }])).toThrow(/ability/);
  expect(deviceRequestPermissions([decrypt])).toEqual([decrypt]);
});

test('refuses two data spaces, overlapping entries, and the named path in other spaces', () => {
  expect(() => deviceRequestPermissions([named, decrypt, { ...named, space: 'default', path: 'notes' }])).toThrow(/one space/);
  expect(() => deviceRequestPermissions([named, { ...named, actions: ['tinycloud.kv/get'] }])).toThrow(/overlaps/);
  expect(() => deviceRequestPermissions([{ ...named, space: 'default' }])).toThrow(/must not address secrets/);
  expect(() => deviceRequestPermissions([{ ...named, space: 'SECRETS' }])).toThrow(/space SECRETS/);
  expect(() => deviceRequestPermissions([named, { ...decrypt, path: 'apps/example' }])).toThrow(/App keys/);
});
