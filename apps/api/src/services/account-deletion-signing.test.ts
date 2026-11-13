import { expect, test } from 'bun:test';
import { Wallet, Signature, recoverAddress, sha256, toUtf8Bytes } from 'ethers';
import { signDeletionInvocation } from './account-deletion-signing';

test('direct owner JWS recovers its owner and binds expiry, nonce and operation key', () => {
  const wallet = Wallet.createRandom();
  const owner = `did:pkh:eip155:1:${wallet.address}`;
  const intent = { resource: owner, action: 'tinycloud.space/retire-owner' as const, hostId: 'node-a', idempotencyKey: crypto.randomUUID() };
  const token = signDeletionInvocation(wallet.privateKey, intent);
  const [header64, payload64, signature64] = token.split('.') as [string, string, string];
  const header = JSON.parse(Buffer.from(header64, 'base64url').toString());
  const payload = JSON.parse(Buffer.from(payload64, 'base64url').toString());
  const bytes = Buffer.from(signature64, 'base64url');
  const sig = Signature.from({ r: `0x${bytes.subarray(0, 32).toString('hex')}`, s: `0x${bytes.subarray(32, 64).toString('hex')}`, v: bytes[64]! + 27 });
  expect(recoverAddress(sha256(toUtf8Bytes(`${header64}.${payload64}`)), sig)).toBe(wallet.address);
  expect(header.alg).toBe('ES256K-R');
  expect(header.jwk.crv).toBe('secp256k1');
  expect(header.ucv).toBe('0.10.0');
  expect(bytes.length).toBe(65);
  expect(payload.iss).toBe(`${owner}#blockchainAccountId`);
  expect(payload.prf).toEqual([]);
  expect(payload.exp - payload.nbf).toBe(300);
  expect(payload.fct).toEqual([{ idempotency_key: intent.idempotencyKey, hostId: intent.hostId }]);
  expect(payload.att).toEqual({ [owner]: { [intent.action]: [{}] } });
  const retry = JSON.parse(Buffer.from(signDeletionInvocation(wallet.privateKey, intent).split('.')[1]!, 'base64url').toString());
  expect(retry.nnc).not.toBe(payload.nnc);
  expect(retry.fct).toEqual(payload.fct);
  expect(() => signDeletionInvocation(wallet.privateKey, { ...intent, resource: 'did:pkh:eip155:1:another' })).toThrow();
});


test('each signed invocation binds exactly one explicit host identity', () => {
  const wallet = Wallet.createRandom();
  const intent = { resource: `did:pkh:eip155:1:${wallet.address}`, action: 'tinycloud.space/list' as const, idempotencyKey: crypto.randomUUID() };
  const tokens = ['node-a', 'node-b'].map(hostId => signDeletionInvocation(wallet.privateKey, { ...intent, hostId }));
  const facts = tokens.map(token => JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()).fct);
  expect(facts).toEqual([[{ idempotency_key: intent.idempotencyKey, hostId: 'node-a' }], [{ idempotency_key: intent.idempotencyKey, hostId: 'node-b' }]]);
  expect(tokens[0]).not.toBe(tokens[1]);
  expect(() => signDeletionInvocation(wallet.privateKey, { ...intent, hostId: '' })).toThrow();
});
