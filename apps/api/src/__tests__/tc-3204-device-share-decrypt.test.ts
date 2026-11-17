import { describe, expect, test } from 'bun:test';
import { DEVICE_AUTH_MAX_SHARE_DECRYPTS, deviceRequestPermissions } from '../services/device-authorization';
import {
  prepareDelegationSession,
  sessionAbilitiesFromPermissions,
  type DelegationPermissionEntry,
} from '../routes/delegate-session';

// TC-3204: a device sign-in may ask to decrypt only exact shared files (`share/<id>` on the approving account's own
// `default` network), at most DEVICE_AUTH_MAX_SHARE_DECRYPTS per request. The whole network, the `share/` prefix, any
// other prefix or key, and app keys are refused, at device start and again when /api/delegate signs.

const DECRYPT = 'tinycloud.encryption/decrypt';
const signer = { address: '0xA8763f2b67aa9C807d2277a698cb071e3D86204A', chainId: 1 };
const other = { address: '0x00000000000000000000000000000000000000bb', chainId: 1 };
const ids = ['3f9c1a7e5b2d48a09c6e1f7a2b4d8c03', '9b0e4d2c7a1f48e3b5c6d7e8f9a0b1c2', 'c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2', '1b2c3d4e-5f60-4718-9a0b-1c2d3e4f5a6b', 'aaaabbbbccccddddeeeeffff00001111'];
const leaf = (path: string): DelegationPermissionEntry & { space: string } => ({ service: 'tinycloud.encryption', space: 'default', path, actions: [DECRYPT] });
const network = (account: { address: string }) => `urn:tinycloud:encryption:did:pkh:eip155:1:${account.address}:default`;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };

const wider: Array<[string, string]> = [
  ['the whole network (empty path)', ''],
  ['the share/ prefix', 'share/'],
  ['the share prefix without a slash', 'share'],
  ['a key below a shared file', `share/${ids[0]}/x`],
  ['another prefix', 'notes/'],
  ['another key', `notes/${ids[0]}`],
  ['a dot segment', 'share/..'],
  ['an id with capitals', 'share/3F9C1A7E5B2D48A09C6E1F7A2B4D8C03'],
  ['an id too short to be a share id', 'share/abc'],
  ['a wildcard', 'share/*'],
];

describe('device start: deviceRequestPermissions (TC-3204)', () => {
  test.each(wider)('refuses decrypt on %s', (_name, path) => {
    expect(() => deviceRequestPermissions([leaf(path)])).toThrow('must name one shared file, share/<id>');
  });

  test.each([
    ['an apps/ key', `apps/xyz.tinycloud.listen/k`],
    ['the apps/ prefix', 'apps/'],
    ['a key URN on the whole network', network(signer)],
  ])('refuses %s as an app key', (_name, path) => {
    expect(() => deviceRequestPermissions([leaf(path)])).toThrow('App keys can only be requested through a website');
  });

  test('refuses a shared file outside the default space', () => {
    expect(() => deviceRequestPermissions([{ ...leaf(`share/${ids[0]}`), space: 'notes' }])).toThrow('must be default for tinycloud.encryption');
  });

  test('accepts one exact shared file, unchanged', () => {
    expect(deviceRequestPermissions([leaf(`share/${ids[0]}`)])).toEqual([leaf(`share/${ids[0]}`)]);
  });

  test(`accepts up to ${DEVICE_AUTH_MAX_SHARE_DECRYPTS} distinct shared files and refuses one more`, () => {
    const allowed = ids.slice(0, DEVICE_AUTH_MAX_SHARE_DECRYPTS).map((id) => leaf(`share/${id}`));
    expect(deviceRequestPermissions(allowed)).toEqual(allowed);
    expect(() => deviceRequestPermissions([...allowed, leaf(`share/${ids[DEVICE_AUTH_MAX_SHARE_DECRYPTS]}`)]))
      .toThrow(`at most ${DEVICE_AUTH_MAX_SHARE_DECRYPTS} shared files`);
  });

  test('refuses the same shared file twice', () => {
    expect(() => deviceRequestPermissions([leaf(`share/${ids[0]}`), leaf(`share/${ids[0]}`)])).toThrow('overlaps permissions[0]');
  });
});

describe('/api/delegate signing with a device transaction: sessionAbilitiesFromPermissions (TC-3204)', () => {
  const device = { deviceTransaction: true };

  test.each(wider)('refuses decrypt on %s', (_name, path) => {
    expect(() => sessionAbilitiesFromPermissions([leaf(path)], signer, device)).toThrow('is not a shared file');
  });

  test.each([
    ['an apps/ key', 'apps/xyz.tinycloud.listen/k'],
    ['a raw URN for the whole network', network(signer)],
    ['a raw URN for the share/ prefix', `${network(signer)}/share/`],
  ])('refuses %s', (_name, path) => {
    expect(() => sessionAbilitiesFromPermissions([leaf(path)], signer, device)).toThrow('is not a shared file');
    expect(() => sessionAbilitiesFromPermissions([{ ...leaf(path), service: 'encryption', space: 'encryption' }], signer, device))
      .toThrow('is not a shared file');
  });

  test('a shared file resolves to that key on the signer own network, and only there', () => {
    const path = `share/${ids[0]}`;
    expect(sessionAbilitiesFromPermissions([leaf(path)], signer, device).rawAbilities).toEqual({ [`${network(signer)}/${path}`]: [DECRYPT] });
    expect(Object.keys(sessionAbilitiesFromPermissions([leaf(path)], other, device).rawAbilities)).toEqual([`${network(other)}/${path}`]);
  });

  test('the prepared SIWE signs each shared file and never the network', () => {
    const paths = ids.slice(0, 3).map((id) => `share/${id}`);
    const { prepared } = prepareDelegationSession({
      address: signer.address, chainId: 1, prefix: 'default', jwk, expiryMs: 3_600_000,
      permissions: paths.map(leaf), deviceTransaction: true,
    });
    const encoded = /^- urn:recap:(.+)$/m.exec(prepared.siwe)?.[1];
    const att = JSON.parse(Buffer.from(encoded!, 'base64url').toString('utf8')).att as Record<string, unknown>;
    expect(Object.keys(att).sort()).toEqual(paths.map((path) => `${network(signer)}/${path}`).sort());
  });
});
