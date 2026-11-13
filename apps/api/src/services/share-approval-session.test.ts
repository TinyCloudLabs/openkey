import { expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { strictSessionDid } from './device-authorization';
import { shareSessionBinding } from './share-approval-session';

test('share approval uses the signed owner, audience and site, never caller labels', async () => {
  const wallet = Wallet.createRandom();
  const publicJwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const sessionDid = strictSessionDid(publicJwk);
  const now = Date.now();
  const siwe = new SiweMessage({ domain: 'thirdparty.example', address: wallet.address,
    uri: sessionDid, version: '1', chainId: 1, nonce: '12345678',
    issuedAt: new Date(now - 1000).toISOString(), expirationTime: new Date(now + 60_000).toISOString(),
  }).prepareMessage();
  const proof = { siwe, signature: await wallet.signMessage(siwe), publicJwk };
  const account = { userId: 'owner', keyId: 'key', address: wallet.address };
  expect(shareSessionBinding(proof, account, 'https://thirdparty.example', now).sessionDid).toBe(sessionDid);
  expect(() => shareSessionBinding(proof, account, 'https://other.example', now)).toThrow();
  expect(() => shareSessionBinding(proof, { ...account, address: Wallet.createRandom().address }, 'https://thirdparty.example', now)).toThrow();
  expect(() => shareSessionBinding({ ...proof, publicJwk: generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }) }, account, 'https://thirdparty.example', now)).toThrow();
  expect(() => shareSessionBinding(proof, account, 'https://thirdparty.example', now + 60_000)).toThrow();
});
