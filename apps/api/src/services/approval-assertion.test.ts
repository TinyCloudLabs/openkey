import { expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { ApprovalContinuations, type ApprovalIdentity } from './approval-continuation';
import { approvalAssertionOptions, verifyApprovalAssertion } from './approval-assertion';
const rp = { rpID: 'openkey.test', origin: 'https://openkey.test' };
const identity: ApprovalIdentity = Object.freeze({ userId: 'u', sessionId: 's', keyId: 'k', keyType: 'MANAGED',
  address: '0xowner', chainId: 1, requestId: 'r', origin: 'https://app.test',
  purpose: 'share-create', serverIntentDigest: 'a'.repeat(64) });
function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = Buffer.concat([Buffer.from('a5010203262001215820', 'hex'), Buffer.from(jwk.x!, 'base64url'),
    Buffer.from('225820', 'hex'), Buffer.from(jwk.y!, 'base64url')]);
  const key = { id: 'p', credentialID: Buffer.from('credential').toString('base64url'),
    publicKey: cose.toString('base64'), counter: 0, countsForStepUp: true, transports: 'internal' };
  let session = true;
  const db = {
    session: { findFirst: async () => session ? { id: 's' } : null },
    ethereumKey: { findFirst: async () => ({ id: 'k', address: '0xowner', keyType: 'MANAGED' }) },
    passkey: { findMany: async () => [key], findFirst: async () => key,
      updateMany: async () => ({ count: 1 }) },
  } as any;
  function assertion(challenge: string, origin = rp.origin, uv = true) {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
    const authenticatorData = Buffer.concat([createHash('sha256').update(rp.rpID).digest(),
      Buffer.from([uv ? 5 : 1, 0, 0, 0, 1])]);
    const signed = Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]);
    return { id: key.credentialID, rawId: key.credentialID, type: 'public-key' as const,
      clientExtensionResults: {}, response: { clientDataJSON: clientDataJSON.toString('base64url'),
        authenticatorData: authenticatorData.toString('base64url'), signature: sign('sha256', signed, privateKey).toString('base64url') } };
  }
  return { db, assertion, expireSession: () => { session = false; } };
}


test('real Share UV is purpose/intent bound and consumed only after one resume', async () => {
  const store = new ApprovalContinuations();
  const { db, assertion } = fixture();
  const { token, options } = await approvalAssertionOptions(db, identity, rp, store);
  await verifyApprovalAssertion(db, token, identity, assertion(options.challenge), rp, store, async () => identity);
  expect(() => store.resume(token, { ...identity, purpose: 'tinycloud-signin' })).toThrow();
  expect(() => store.resume(token, { ...identity, serverIntentDigest: 'b'.repeat(64) })).toThrow();
  expect(() => store.consume(token, identity, () => true)).toThrow();
  store.resume(token, identity);
  expect(() => store.resume(token, identity)).toThrow();
  let consumed = false;
  store.consume(token, identity, () => { consumed = true; return true; });
  expect(consumed).toBe(true);
  expect(() => store.consume(token, identity, () => true)).toThrow();
});
for (const failure of ['origin', 'uv', 'session', 'digest'] as const) {
  test(`real Share assertion rejects ${failure} and cancels the exact continuation`, async () => {
    const store = new ApprovalContinuations();
    const { db, assertion } = fixture();
    const { token, options } = await approvalAssertionOptions(db, identity, rp, store);
    await expect(verifyApprovalAssertion(db, token, identity, assertion(options.challenge,
      failure === 'origin' ? 'https://evil.test' : rp.origin, failure !== 'uv'), rp, store,
      async () => { if (failure === 'session') throw new Error('signed out');
        return failure === 'digest' ? { ...identity, serverIntentDigest: 'b'.repeat(64) } : identity;
      })).rejects.toThrow();
    expect(() => store.identity(token, identity)).toThrow();
  });
}
