// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { expectedSignerAddress } from './delegate-expected-signer';

const owner = '0xA8763f2b67aa9C807d2277a698cb071e3D86204A';
const other = '0x1111111111111111111111111111111111111111';
const space = (address: string) => `tinycloud:pkh:eip155:1:${address}:secrets`;
const network = (address: string) => `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default`;

describe('expectedSignerAddress', () => {
  test('a secrets request with a raw decrypt grant still pins its owner', () => {
    expect(expectedSignerAddress([
      { service: 'tinycloud.kv', space: space(owner), path: 'vault/secrets/TC_FWD_TOKEN' },
      { service: 'tinycloud.encryption', space: 'encryption', path: network(owner) },
      { service: 'tinycloud.encryption', path: network(owner) },
      { service: 'tinycloud.capabilities', space: space(owner), path: '' },
    ])).toBe(owner.toLowerCase());
  });

  test('a raw network owned by another account pins nothing', () => {
    expect(expectedSignerAddress([
      { service: 'tinycloud.kv', space: space(owner), path: 'vault/secrets/TC_FWD_TOKEN' },
      { service: 'tinycloud.encryption', space: 'encryption', path: network(other) },
    ])).toBeNull();
  });

  test('a short-name space pins nothing', () => {
    expect(expectedSignerAddress([{ service: 'tinycloud.kv', space: 'default', path: 'notes' }])).toBeNull();
  });
});
