import { expect, test } from 'bun:test';
import { SignInContinuations, type SignInIdentity } from './signin-continuation';
import { checkAuthorizationContext, checkPreviewApproval, consumeCheckedAuthorizationContext,
  issueAuthorizationContext, issuePreviewApproval } from './authorization-signing';

test('continuation and actual authorization/preview claims are spent together exactly once', () => {
  const store = new SignInContinuations();
  const identity: SignInIdentity = { userId: 'u', sessionId: 's', requestId: 'r', keyId: 'k',
    address: '0x1111111111111111111111111111111111111111', keyType: 'MANAGED', chainId: 1, origin: 'https://app.test' };
  const pending = store.issue(identity);
  store.verified(pending.token, identity, pending.challenge);
  const common = { userId: identity.userId, keyId: identity.keyId, keyAddress: identity.address,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    host: 'https://node.test', spaceId: 'space' };
  const issued = issueAuthorizationContext({ ...common, baselineAbilitiesDigest: 'baseline',
    immutableFieldsDigest: 'immutable', allowedActionIds: new Set(['get']), initialSelectionActionIds: new Set(['get']),
    expirationTime: new Date(Date.now() + 86_400_000).toISOString(), signInContinuation: { token: pending.token, identity } });
  const preview = issuePreviewApproval({ authorizationContextToken: issued.token, userId: identity.userId,
    keyAddress: identity.address, selectedActionIds: new Set(['get']), signedMessage: 'exact approved bytes' });
  const authorization = checkAuthorizationContext({ ...common, token: issued.token,
    selectedActionIds: new Set(['get']), candidateImmutableFieldsDigest: 'immutable', requiredActionIds: new Set() });
  const checkedPreview = checkPreviewApproval({ token: preview.token, authorizationContextToken: issued.token,
    userId: identity.userId, keyAddress: identity.address, selectedActionIds: new Set(['get']),
    candidateSignedMessage: 'exact approved bytes' });
  if (!authorization.ok || !checkedPreview.ok) throw new Error('Expected valid checked claims');
  store.consume(pending.token, identity, () => consumeCheckedAuthorizationContext(authorization.claim, checkedPreview.claim).ok);
  expect(consumeCheckedAuthorizationContext(authorization.claim, checkedPreview.claim).ok).toBe(false);
  let attemptedAgain = false;
  expect(() => store.consume(pending.token, identity, () => { attemptedAgain = true; return true; })).toThrow();
  expect(attemptedAgain).toBe(false);
});
