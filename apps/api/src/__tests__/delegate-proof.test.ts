import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import {
  delegationResponse,
  verifyDelegationProof,
} from '../routes/delegate-proof';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const jwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
};

function preparedSession() {
  return prepareSession({
    address: account.address,
    chainId: 1,
    domain: 'cli.tinycloud.xyz',
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    spaceId: `tinycloud:pkh:eip155:1:${account.address}:default`,
    jwk,
    abilities: { kv: { '': ['tinycloud.kv/get'] } },
  });
}

async function responseFor(signatureMode: 'managed' | 'external') {
  const prepared = preparedSession();
  const siwe = String(prepared.siwe);
  const signature = await account.signMessage({ message: siwe });
  const proof = await verifyDelegationProof(
    siwe,
    signature,
    signatureMode === 'managed' ? account.address : undefined,
  );
  return delegationResponse({
    delegationHeader: { Authorization: 'authorization' },
    delegationCid: 'bafybeigdyrzt5example',
    verificationMethod: prepared.verificationMethod,
  }, {
    spaceId: prepared.spaceId,
    jwk,
    proof,
    hostActivated: false,
    edited: false,
  });
}

describe('delegation completion proof responses', () => {
  test.each(['managed', 'external'] as const)(
    'returns a complete verified tuple for the %s path',
    async (signatureMode) => {
      const response = await responseFor(signatureMode);

      expect(response.address).toBe(account.address);
      expect(response.chainId).toBe(1);
      expect(typeof response.siwe).toBe('string');
      expect(/^0x[0-9a-f]{130}$/i.test(response.signature)).toBe(true);
      expect(typeof response.expirationTime).toBe('string');
      expect(typeof response.expiresAt).toBe('string');
      expect(typeof response.expiry).toBe('string');
      expect(response.ownerDid).toBe(`did:pkh:eip155:1:${account.address}`);
      expect(response.expiresAt).toBe(response.expirationTime);
      expect(response.expiry).toBe(response.expirationTime);
      expect(Date.parse(response.expiresAt)).toBeGreaterThan(Date.now());

      const verified = await verifyDelegationProof(
        response.siwe,
        response.signature,
        response.address,
      );
      expect(verified.address).toBe(response.address);
      expect(verified.chainId).toBe(response.chainId);
      expect(verified.expirationTime).toBe(response.expiresAt);
    },
  );

  test('rejects a signature that does not verify against the signed owner', async () => {
    const prepared = preparedSession();
    const siwe = String(prepared.siwe);
    const wrongAccount = privateKeyToAccount(
      '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
    );
    const signature = await wrongAccount.signMessage({ message: siwe });

    await expect(verifyDelegationProof(siwe, signature, account.address))
      .rejects.toThrow('signature owner mismatch');
  });
});
