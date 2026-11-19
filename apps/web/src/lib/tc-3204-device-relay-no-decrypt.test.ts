// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { approvedDevicePermissions, type DevicePermission } from './device-authorization';

// TC-3204: device sign-in grants no encryption ability. The /delegate page refuses to relay a signed delegation that
// carries any encryption grant, even one the device request listed.

const address = '0x00000000000000000000000000000000000000Aa';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default`;
const DECRYPT = 'tinycloud.encryption/decrypt';
const kv: DevicePermission = { service: 'tinycloud.kv', space: 'default', path: 'notes/', actions: ['tinycloud.kv/get'] };
const kvGrant = { service: 'kv', space, path: 'notes/', actions: ['tinycloud.kv/get'] };

const cases: Array<[string, DevicePermission, Record<string, unknown>]> = [
  ['the default network for the base default-space entry',
    { service: 'tinycloud.encryption', space: 'default', path: '', actions: [DECRYPT] },
    { service: 'encryption', space: 'encryption', path: network, actions: [DECRYPT] }],
  ['the network URN requested as written',
    { service: 'tinycloud.encryption', space: 'encryption', path: network, actions: [DECRYPT] },
    { service: 'encryption', space: 'encryption', path: network, actions: [DECRYPT] }],
  ['a space-scoped entry requested as written',
    { service: 'tinycloud.encryption', space, path: 'share/', actions: [DECRYPT] },
    { service: 'encryption', space, path: 'share/', actions: [DECRYPT] }],
  // The page prefixes names lacking a lower-case `tinycloud.`, so this request spelling would otherwise match.
  ['an upper-case full service name',
    { service: 'tinycloud.TINYCLOUD.ENCRYPTION', space, path: 'share/', actions: [DECRYPT] },
    { service: 'TINYCLOUD.ENCRYPTION', space, path: 'share/', actions: [DECRYPT] }],
];

describe('approvedDevicePermissions refuses every encryption grant (TC-3204)', () => {
  test.each(cases)('refuses decrypt on %s', (_name: string, requested: DevicePermission, grant: Record<string, unknown>) => {
    expect(() => approvedDevicePermissions([kv, requested], [kvGrant, grant])).toThrow('The approved delegation exceeds the device request.');
  });

  test('still maps a kv-only grant', () => {
    expect(approvedDevicePermissions([kv], [kvGrant])).toEqual([kv]);
  });
});
