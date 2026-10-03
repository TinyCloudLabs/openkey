// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { expectedSigner } from './delegate-expected-signer';

const owner = '0xA8763f2b67aa9C807d2277a698cb071e3D86204A';
const other = '0x1111111111111111111111111111111111111111';
const space = (address: string, chain = 1) => `tinycloud:pkh:eip155:${chain}:${address}:secrets`;
const network = (address: string, chain = 1) => `urn:tinycloud:encryption:did:pkh:eip155:${chain}:${address}:default`;
const kv = { service: 'tinycloud.kv', space: space(owner), path: 'vault/secrets/TC_FWD_TOKEN' };

describe('expectedSigner', () => {
  test('a secrets request with a raw decrypt grant still pins its owner', () => {
    expect(expectedSigner([
      kv,
      { service: 'tinycloud.encryption', space: 'encryption', path: network(owner) },
      { service: 'tinycloud.encryption', path: network(owner) },
      { service: 'tinycloud.capabilities', space: space(owner), path: '' },
    ])).toEqual({ kind: 'owner', chainId: '1', address: owner.toLowerCase() });
  });

  test('a raw network owned by another account is a conflict', () => {
    expect(expectedSigner([kv, { service: 'tinycloud.encryption', space: 'encryption', path: network(other) }]))
      .toEqual({ kind: 'conflict', owners: [`did:pkh:eip155:1:${owner.toLowerCase()}`, `did:pkh:eip155:1:${other}`] });
  });

  test('the same address on another chain is a conflict, not a pin', () => {
    expect(expectedSigner([kv, { service: 'tinycloud.encryption', space: 'encryption', path: network(owner, 10) }]).kind)
      .toBe('conflict');
  });

  test('a short-name space or a malformed entry pins nothing', () => {
    expect(expectedSigner([{ service: 'tinycloud.kv', space: 'default', path: 'notes' }])).toEqual({ kind: 'none' });
    for (const malformed of [
      { service: 'tinycloud.encryption', space: 'encryption' },
      { service: 7, path: network(owner) },
      null,
      'tinycloud.kv',
    ]) {
      expect(expectedSigner([kv, malformed]), JSON.stringify(malformed)).toEqual({ kind: 'none' });
    }
  });
});
