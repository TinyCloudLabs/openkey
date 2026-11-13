import { expect, test } from 'bun:test';
import { assertSignInSiwe } from './signin-assertion';
import { sessionDidForPublicJwk } from './device-authorization';
import type { SignInIdentity } from './signin-continuation';

const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const address = '0x1111111111111111111111111111111111111111';
const identity: SignInIdentity = { userId: 'u', sessionId: 's', requestId: 'r', keyId: 'k',
  keyType: 'MANAGED', address, chainId: 1, origin: 'https://app.test' };
const message = `app.test wants you to sign in with your Ethereum account:\n${address}\n\nSign in\n\nURI: ${sessionDidForPublicJwk(jwk)}\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-11-13T00:00:00.000Z`;

test('DID session URI must derive from the request public JWK', () => {
  expect(() => assertSignInSiwe(message, jwk, identity)).not.toThrow();
  expect(() => assertSignInSiwe(message, { ...jwk, x: 'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, identity)).toThrow('session URI');
});

for (const [name, changed] of Object.entries({
  domain: message.replace('app.test wants', 'evil.test wants'),
  webURI: message.replace(sessionDidForPublicJwk(jwk), 'https://evil.test'),
  owner: message.replace(address, '0x2222222222222222222222222222222222222222'),
  chain: message.replace('Chain ID: 1', 'Chain ID: 2'),
})) {
  test(`refuses ${name} substitution before preparing authorization`, () => {
    expect(() => assertSignInSiwe(changed, jwk, identity)).toThrow();
  });
}
