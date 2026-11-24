import { describe, expect, test } from 'bun:test';
import { deviceRequestPermissions } from '../services/device-authorization';
import { DEVICE_SECRETS_REFUSAL } from '../services/device-flow-abilities';
import { sessionAbilitiesFromPermissions, type DelegationPermissionEntry } from '../routes/delegate-session';

// Device sign-in can't ask to decrypt. Every tinycloud.encryption entry, under its full or short name in any
// case and in any shape, is refused at device start (invalid_scope) and again when /api/delegate signs for a device
// transaction (invalid_permissions). Other spellings fail the device-flow allowlist (tc-3204-device-allowlist.test.ts).

const DECRYPT = 'tinycloud.encryption/decrypt';
const signer = { address: '0xA8763f2b67aa9C807d2277a698cb071e3D86204A', chainId: 1 };
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${signer.address}:default`;
const kv = { service: 'tinycloud.kv', space: 'default', path: 'notes/', actions: ['tinycloud.kv/get'] };
const capabilities = { service: 'tinycloud.capabilities', space: 'default', path: '', actions: ['tinycloud.capabilities/read'] };
const decrypt = { service: 'tinycloud.encryption', space: 'default', path: '', actions: [DECRYPT] };

const encryptionEntries: Array<[string, DelegationPermissionEntry & { space: string }]> = [
  ['the whole default network (empty path)', decrypt],
  ['one shared file', { ...decrypt, path: 'share/3f9c1a7e5b2d48a09c6e1f7a2b4d8c03' }],
  ['the share/ prefix', { ...decrypt, path: 'share/' }],
  ['another key', { ...decrypt, path: 'notes/x' }],
  ['the network URN', { ...decrypt, space: 'encryption', path: network }],
  ['the short service name', { ...decrypt, service: 'encryption' }],
  ['an upper-case service name', { ...decrypt, service: 'TINYCLOUD.ENCRYPTION' }],
  ['a mixed-case short service name', { ...decrypt, service: 'Encryption' }],
  ['encrypt', { ...decrypt, actions: ['tinycloud.encryption/encrypt'] }],
  ['key.create', { ...decrypt, actions: ['tinycloud.encryption/key.create'] }],
];

describe('device start refuses every encryption entry', () => {
  // A key URN path keeps the app-key wording (app-key-refusal-keys-handoff-device.test.ts).
  test.each(encryptionEntries.filter(([name]) => name !== 'the network URN'))('refuses %s alone and beside kv + capabilities/read', (_name, entry) => {
    for (const permissions of [[entry], [kv, capabilities, entry], [entry, kv, capabilities]]) {
      let refused: unknown;
      try {
        deviceRequestPermissions(permissions);
      } catch (error) {
        refused = error;
      }
      expect(refused).toMatchObject({ code: 'invalid_scope', status: 400 });
      expect((refused as Error).message).toBe(DEVICE_SECRETS_REFUSAL);
    }
  });

  test('still admits kv + capabilities/read', () => {
    expect(deviceRequestPermissions([kv, capabilities])).toEqual([kv, capabilities]);
  });
});

describe('/api/delegate signing for a device transaction refuses every encryption entry', () => {
  test.each(encryptionEntries)('refuses %s', (_name, entry) => {
    expect(() => sessionAbilitiesFromPermissions([capabilities, entry], signer, { deviceTransaction: true }))
      .toThrow(DEVICE_SECRETS_REFUSAL);
  });

  test('signs kv + capabilities/read and no encryption resource', () => {
    const abilities = sessionAbilitiesFromPermissions([kv, capabilities], signer, { deviceTransaction: true });
    expect(Object.keys(abilities.rawAbilities)).toEqual([]);
  });
});
