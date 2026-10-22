import { describe, expect, test } from 'bun:test';
import { DelegateRequestError } from '../routes/delegate-validation';
import {
  parsePreparedRecap,
  prepareDelegationSession,
  sessionAbilitiesFromPermissions,
  type DelegationPermissionEntry,
} from '../routes/delegate-session';

// TC-1778: a device authorization requests one encryption entry — service
// `tinycloud.encryption`, space `default`, empty path, decrypt only. At prepare
// it resolves to the signer's own `default` network. Any other entry, and any
// entry on a non-device route, keeps its existing handling.

const signerChecksum = '0xA8763f2b67aa9C807d2277a698cb071e3D86204A';
const otherChecksum = '0x00000000000000000000000000000000000000bb';
const chainId = 1;
const DECRYPT = 'tinycloud.encryption/decrypt';
const device: DelegationPermissionEntry = {
  service: 'tinycloud.encryption',
  space: 'default',
  path: '',
  actions: [DECRYPT],
};
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const expiryMs = 60 * 60 * 1000;

function networkUrn(address: string): string {
  return `urn:tinycloud:encryption:did:pkh:eip155:${chainId}:${address}:default`;
}

/** The signed ReCap `att` map, decoded from the SIWE's `urn:recap:` resource. */
function recapAtt(siwe: string): Record<string, Record<string, unknown[]>> {
  const encoded = /^- urn:recap:(.+)$/m.exec(siwe)?.[1];
  if (!encoded) throw new Error('SIWE has no ReCap resource');
  return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')).att;
}

function prepareDevice(address: string, permissions: DelegationPermissionEntry[] = [device], deviceTransaction = true) {
  return prepareDelegationSession({
    address,
    chainId,
    prefix: 'default',
    jwk,
    permissions,
    expiryMs,
    deviceTransaction,
  });
}

describe('sessionAbilitiesFromPermissions — device default encryption entry (TC-1778)', () => {
  test('resolves the exact entry to the signer own default network as a raw network', () => {
    expect(sessionAbilitiesFromPermissions([device], { address: signerChecksum, chainId }, { deviceTransaction: true })).toEqual({
      abilities: {},
      rawAbilities: { [networkUrn(signerChecksum)]: [DECRYPT] },
    });
  });

  test('two accounts: each signer resolves to its own network only', () => {
    const forOther = sessionAbilitiesFromPermissions([device], { address: otherChecksum, chainId }, { deviceTransaction: true });
    expect(Object.keys(forOther.rawAbilities)).toEqual([networkUrn(otherChecksum)]);
  });

  test('refuses a second exact entry in the same device request', () => {
    expect(() => sessionAbilitiesFromPermissions([device, device], { address: signerChecksum, chainId }, { deviceTransaction: true })).toThrow(DelegateRequestError);
    expect(() => sessionAbilitiesFromPermissions([device, device], { address: signerChecksum, chainId }, { deviceTransaction: true })).toThrow('repeats the default encryption entry');
  });

  test('a non-device /delegate prepare carrying the same entry is unchanged', () => {
    expect(sessionAbilitiesFromPermissions([device], { address: signerChecksum, chainId })).toEqual({
      abilities: { encryption: { '': [DECRYPT] } },
      rawAbilities: {},
    });
  });

  test('a different path on the device route is unchanged', () => {
    const other = { ...device, path: 'x' };
    expect(sessionAbilitiesFromPermissions([other], { address: signerChecksum, chainId }, { deviceTransaction: true }))
      .toEqual(sessionAbilitiesFromPermissions([other], { address: signerChecksum, chainId }));
  });

  test('a different space on the device route is unchanged', () => {
    const other = { ...device, space: 'encryption' };
    expect(sessionAbilitiesFromPermissions([other], { address: signerChecksum, chainId }, { deviceTransaction: true }))
      .toEqual(sessionAbilitiesFromPermissions([other], { address: signerChecksum, chainId }));
  });

  test('a different ability set on the device route is unchanged', () => {
    const other = { ...device, actions: [DECRYPT, 'tinycloud.encryption/encrypt'] };
    expect(sessionAbilitiesFromPermissions([other], { address: signerChecksum, chainId }, { deviceTransaction: true }))
      .toEqual(sessionAbilitiesFromPermissions([other], { address: signerChecksum, chainId }));
  });
});

describe('prepareDelegationSession — device default encryption entry (TC-1778)', () => {
  test('signs the signer own default network as a top-level raw resource', () => {
    const result = prepareDevice(signerChecksum);
    expect(recapAtt(result.prepared.siwe)).toEqual({ [networkUrn(signerChecksum)]: { [DECRYPT]: [{}] } });
    expect(parsePreparedRecap(result.prepared.siwe)).toContainEqual({
      service: 'encryption',
      space: 'encryption',
      path: networkUrn(signerChecksum),
      actions: [DECRYPT],
    });
  });

  test('two accounts sign different networks', () => {
    const mine = recapAtt(prepareDevice(signerChecksum).prepared.siwe);
    const theirs = recapAtt(prepareDevice(otherChecksum).prepared.siwe);
    expect(Object.keys(mine)).toEqual([networkUrn(signerChecksum)]);
    expect(Object.keys(theirs)).toEqual([networkUrn(otherChecksum)]);
  });

  test('a non-device prepare of the same entry signs no raw network', () => {
    const result = prepareDevice(signerChecksum, [device], false);
    expect(result.prepared.siwe).not.toContain('urn:tinycloud:encryption:');
  });
});
