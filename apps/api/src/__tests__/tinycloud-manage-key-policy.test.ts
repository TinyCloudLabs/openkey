import { describe, expect, test } from 'bun:test';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { validateTinyCloudManageKeyRequest } from '../services/tinycloud-manage-key-policy';

const account = privateKeyToAccount(
  '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
);
const identity = { keyId: 'canonical-key', address: account.address, chainId: 1 as const };

function validMessage() {
  return prepareSession({
    address: account.address,
    chainId: 1,
    domain: 'app.example',
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 60_000).toISOString(),
    spaceId: `tinycloud:pkh:eip155:1:${account.address}:applications`,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    abilities: { kv: { marker: ['tinycloud.kv/get'] } },
  }).siwe;
}

describe('tinycloud:manage-key structural signing policy', () => {
  test('accepts a TinyCloud SIWE/ReCap for the canonical applications space', () => {
    expect(validateTinyCloudManageKeyRequest({
      type: 'siwe', chainId: 1, message: validMessage(), identity,
    })).toEqual({ allowed: true });
  });

  test('rejects plain messages and a different owner space', () => {
    expect(validateTinyCloudManageKeyRequest({
      type: 'message', chainId: 1, message: 'sign this', identity,
    }).allowed).toBe(false);

    const other = privateKeyToAccount(
      '0x1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    );
    const message = prepareSession({
      address: other.address,
      chainId: 1,
      domain: 'app.example',
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + 60_000).toISOString(),
      spaceId: `tinycloud:pkh:eip155:1:${other.address}:applications`,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
      abilities: { kv: { marker: ['tinycloud.kv/get'] } },
    }).siwe;
    expect(validateTinyCloudManageKeyRequest({
      type: 'siwe', chainId: 1, message, identity,
    }).allowed).toBe(false);
  });

  test('rejects an expired session and a non-canonical subspace', () => {
    const expired = prepareSession({
      address: account.address,
      chainId: 1,
      domain: 'app.example',
      issuedAt: new Date(Date.now() - 120_000).toISOString(),
      expirationTime: new Date(Date.now() - 60_000).toISOString(),
      spaceId: `tinycloud:pkh:eip155:1:${account.address}:applications`,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
      abilities: { kv: { marker: ['tinycloud.kv/get'] } },
    }).siwe;
    expect(validateTinyCloudManageKeyRequest({
      type: 'siwe', chainId: 1, message: expired, identity,
    }).allowed).toBe(false);

    const otherSpace = prepareSession({
      address: account.address,
      chainId: 1,
      domain: 'app.example',
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + 60_000).toISOString(),
      spaceId: `tinycloud:pkh:eip155:1:${account.address}:secrets`,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
      abilities: { kv: { marker: ['tinycloud.kv/get'] } },
    }).siwe;
    expect(validateTinyCloudManageKeyRequest({
      type: 'siwe', chainId: 1, message: otherSpace, identity,
    }).allowed).toBe(false);
  });
});
