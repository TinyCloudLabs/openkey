import { parseStrictSiwe } from './signed-subset';
import { checkSiweOrigin } from './siwe-origin';
import { sessionDidForPublicJwk } from './device-authorization';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { approvalAssertionOptions, verifyApprovalAssertion, type Database, type RelyingParty } from './approval-assertion';
import { SignInContinuations, type SignInIdentity } from './signin-continuation';

export const signInContinuations = new SignInContinuations();

/** Reload the server's identity on every phase; browser key metadata is never authority. */
export async function currentSignInIdentity(db: Database, userId: string, sessionId: string,
  requestId: string, origin: string, keyId: string, chainId: number): Promise<SignInIdentity> {
  const [session, key] = await Promise.all([
    db.session.findFirst({ where: { id: sessionId, userId, expiresAt: { gt: new Date() } } }),
    db.ethereumKey.findFirst({ where: { id: keyId, userId, archivedAt: null } }),
  ]);
  if (!session || !key || (key.keyType !== 'MANAGED' && key.keyType !== 'EXTERNAL')) {
    throw new Error('Sign-in account or key changed');
  }
  return { userId, sessionId, requestId, origin, keyId: key.id, keyType: key.keyType,
    address: key.address.toLowerCase(), chainId };
}

export function signInAssertionOptions(db: Database, identity: SignInIdentity, rp: RelyingParty) {
  return approvalAssertionOptions(db, identity, rp, signInContinuations);
}

export function verifySignInAssertion(db: Database, token: string, identity: SignInIdentity,
  response: AuthenticationResponseJSON, rp: RelyingParty): Promise<void> {
  return verifyApprovalAssertion(db, token, identity, response, rp, signInContinuations,
    () => currentSignInIdentity(db, identity.userId, identity.sessionId,
      identity.requestId, identity.origin, identity.keyId, identity.chainId));
}

/** Bind the provisional identity to the caller's actual session request. */
export function assertSignInSiwe(message: string, jwk: unknown, identity: SignInIdentity): void {
  const origin = checkSiweOrigin(message, identity.origin);
  const parsed = parseStrictSiwe(message);
  if (!origin.siwe || !origin.ok || !parsed.ok ||
      parsed.siwe.address.toLowerCase() !== identity.address || Number(parsed.siwe.chainId) !== identity.chainId) {
    throw new Error('SIWE does not match sign-in identity');
  }
  if (new URL(parsed.siwe.uri).protocol.toLowerCase() === 'did:' && parsed.siwe.uri !== sessionDidForPublicJwk(jwk)) {
    throw new Error('SIWE session URI does not match public session JWK');
  }
}
