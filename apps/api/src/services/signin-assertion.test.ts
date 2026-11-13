import { expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { signInAssertionOptions, signInContinuations, verifySignInAssertion } from './signin-assertion';
import type { SignInIdentity } from './signin-continuation';

const rp = { rpID: 'openkey.test', origin: 'https://openkey.test' };
const identity: SignInIdentity = { userId: 'u', sessionId: 's', keyId: 'k', keyType: 'MANAGED',
  address: '0xowner', chainId: 1, requestId: 'r', origin: 'https://app.test' };

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

test('a real UV assertion verifies only the server request-bound challenge', async () => {
  const { db, assertion } = fixture();
  const { token, options } = await signInAssertionOptions(db, identity, rp);
  expect(options.userVerification).toBe('required');
  await verifySignInAssertion(db, token, identity, assertion(options.challenge), rp);
  expect(signInContinuations.identity(token, identity)).toEqual(identity);
  await expect(verifySignInAssertion(db, token, identity, assertion(options.challenge), rp)).rejects.toThrow();
});

for (const failure of ['challenge', 'origin', 'uv', 'session'] as const) {
  test(`a real assertion refuses ${failure} mismatch and invalidates continuation`, async () => {
    const { db, assertion, expireSession } = fixture();
    const { token, options } = await signInAssertionOptions(db, identity, rp);
    if (failure === 'session') expireSession();
    await expect(verifySignInAssertion(db, token, identity, assertion(
      failure === 'challenge' ? 'wrong' : options.challenge,
      failure === 'origin' ? 'https://evil.test' : rp.origin, failure !== 'uv'), rp)).rejects.toThrow();
    expect(() => signInContinuations.identity(token, identity)).toThrow();
  });
}
