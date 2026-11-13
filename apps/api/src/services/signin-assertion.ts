import { parseStrictSiwe } from './signed-subset';
import { checkSiweOrigin } from './siwe-origin';
import { sessionDidForPublicJwk } from './device-authorization';
import { generateAuthenticationOptions, verifyAuthenticationResponse,
  type AuthenticationResponseJSON, type AuthenticatorTransportFuture } from '@simplewebauthn/server';
import type { PrismaClient } from '@openkey/db';
import { SignInContinuations, type SignInIdentity } from './signin-continuation';

export const signInContinuations = new SignInContinuations();
type Database = Pick<PrismaClient, 'passkey' | 'session' | 'ethereumKey'>;
type RelyingParty = { rpID: string; origin: string };

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

export async function signInAssertionOptions(db: Database, identity: SignInIdentity, rp: RelyingParty) {
  const passkeys = await db.passkey.findMany({ where: { userId: identity.userId, countsForStepUp: true } });
  if (!passkeys.length) throw new Error('Sign-in requires an eligible passkey');
  const { token, challenge } = signInContinuations.issue(identity);
  try {
    const options = await generateAuthenticationOptions({ rpID: rp.rpID, challenge: new Uint8Array(Buffer.from(challenge, 'base64url')),
      userVerification: 'required', allowCredentials: passkeys.map((key) => ({
        id: key.credentialID,
        transports: key.transports ? key.transports.split(',') as AuthenticatorTransportFuture[] : undefined,
      })),
    });
    return { token, options };
  } catch (error) {
    signInContinuations.cancel(token, identity);
    throw error;
  }
}

export async function verifySignInAssertion(db: Database, token: string, identity: SignInIdentity,
  response: AuthenticationResponseJSON, rp: RelyingParty): Promise<void> {
  const challenge = signInContinuations.challenge(token, identity);
  try {
    const key = await db.passkey.findFirst({ where: {
      credentialID: response.id, userId: identity.userId, countsForStepUp: true,
    } });
    if (!key) throw new Error('Sign-in passkey not found');
    const verified = await verifyAuthenticationResponse({ response, expectedChallenge: challenge,
      expectedOrigin: rp.origin, expectedRPID: rp.rpID, requireUserVerification: true,
      credential: { id: key.credentialID, publicKey: new Uint8Array(Buffer.from(key.publicKey, 'base64')),
        counter: key.counter },
    });
    if (!verified.verified || verified.authenticationInfo.userVerified !== true) {
      throw new Error('Sign-in assertion requires user verification');
    }
    const updated = await db.passkey.updateMany({ where: { id: key.id, userId: identity.userId,
      countsForStepUp: true, counter: key.counter }, data: { counter: verified.authenticationInfo.newCounter } });
    if (updated.count !== 1) throw new Error('Sign-in passkey changed');
    // Recheck after the assertion's awaits, including session expiry and key archival.
    const current = await currentSignInIdentity(db, identity.userId, identity.sessionId,
      identity.requestId, identity.origin, identity.keyId, identity.chainId);
    signInContinuations.verified(token, current, challenge);
  } catch (error) {
    try { signInContinuations.cancel(token, identity); } catch { /* already cancelled or expired */ }
    throw error;
  }
}

/** Bind the provisional identity to the caller's actual session request. */
export function assertSignInSiwe(message: string, jwk: unknown, identity: SignInIdentity): void {
  const origin = checkSiweOrigin(message, identity.origin);
  const parsed = parseStrictSiwe(message);
  if (!origin.siwe || !origin.ok || !parsed.ok ||
      parsed.siwe.address.toLowerCase() !== identity.address || Number(parsed.siwe.chainId) !== identity.chainId) {
    throw new Error('SIWE does not match sign-in identity');
  }
  if (parsed.siwe.uri.startsWith('did:') && parsed.siwe.uri !== sessionDidForPublicJwk(jwk)) {
    throw new Error('SIWE session URI does not match public session JWK');
  }
}
