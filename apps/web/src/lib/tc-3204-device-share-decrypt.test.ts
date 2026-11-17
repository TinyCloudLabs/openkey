// TC-3204: a device request decrypts only exact shared files. The relay maps a signed grant back onto the request only
// when it is that shared file on the signer's own default network; the whole network or the share/ prefix never maps.

// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { approvedDevicePermissions, isDeviceShareDecryptEntry, type DevicePermission } from './device-authorization';

const DECRYPT = 'tinycloud.encryption/decrypt';
const alice = { address: '0x00000000000000000000000000000000000000Aa', chainId: 1 };
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${alice.address}:default`;
const share = 'share/3f9c1a7e5b2d48a09c6e1f7a2b4d8c03';
const requested: DevicePermission[] = [{ service: 'tinycloud.encryption', space: 'default', path: share, actions: [DECRYPT] }];
const grant = (path: string) => ({ service: 'encryption', space: 'encryption', path, actions: [DECRYPT] });
const EXCEEDS = 'The approved delegation exceeds the device request.';

describe('device shared-file decrypt relay (TC-3204)', () => {
  test('the exact shared file maps back to the request', () => {
    expect(approvedDevicePermissions(requested, [grant(`${network}/${share}`)], alice)).toEqual(requested);
  });

  test.each([
    ['the whole network', network],
    ['the share/ prefix', `${network}/share/`],
    ['another shared file', `${network}/share/9b0e4d2c7a1f48e3b5c6d7e8f9a0b1c2`],
    ['a key below the shared file', `${network}/${share}/x`],
    ['the shared file id in capitals', `${network}/${share.toUpperCase()}`],
  ])('refuses a signed grant on %s', (_name: string, path: string) => {
    expect(() => approvedDevicePermissions(requested, [grant(path)], alice)).toThrow(EXCEEDS);
  });

  test.each([
    ['the whole network', ''],
    ['the share/ prefix', 'share/'],
    ['another prefix', 'notes/'],
    ['an apps/ key', 'apps/xyz.tinycloud.listen/k'],
  ])('a request entry on %s is not a shared file', (_name: string, path: string) => {
    const entry = { ...requested[0]!, path };
    expect(isDeviceShareDecryptEntry(entry)).toBe(false);
    expect(() => approvedDevicePermissions([entry], [grant(path ? `${network}/${path}` : network)], alice)).toThrow(EXCEEDS);
  });
});
