import { generateAuthenticationOptions, verifyAuthenticationResponse,
  type AuthenticationResponseJSON, type AuthenticatorTransportFuture } from '@simplewebauthn/server';
import type { PrismaClient } from '@openkey/db';
import type { SignInIdentity } from './signin-continuation';

export type Database = Pick<PrismaClient, 'passkey' | 'session' | 'ethereumKey'>;
export type RelyingParty = { rpID: string; origin: string };
export interface AssertionStore<I> {
  issue(identity: I): { token: string; challenge: string };
  challenge(token: string, identity: I): string;
  verified(token: string, identity: I, challenge: string): void;
  cancel(token: string, identity: I): void;
}

export async function approvalAssertionOptions<I extends SignInIdentity>(db: Database, identity: I, rp: RelyingParty, store: AssertionStore<I>) {
  const passkeys = await db.passkey.findMany({ where: { userId: identity.userId, countsForStepUp: true } });
  if (!passkeys.length) throw new Error('Sign-in requires an eligible passkey');
  const { token, challenge } = store.issue(identity);
  try {
    const options = await generateAuthenticationOptions({ rpID: rp.rpID, challenge: new Uint8Array(Buffer.from(challenge, 'base64url')),
      userVerification: 'required', allowCredentials: passkeys.map((key) => ({
        id: key.credentialID,
        transports: key.transports ? key.transports.split(',') as AuthenticatorTransportFuture[] : undefined,
      })),
    });
    return { token, options };
  } catch (error) {
    store.cancel(token, identity);
    throw error;
  }
}

export async function verifyApprovalAssertion<I extends SignInIdentity>(db: Database, token: string, identity: I,
  response: AuthenticationResponseJSON, rp: RelyingParty, store: AssertionStore<I>, reloadIdentity: () => Promise<I>): Promise<void> {
  const challenge = store.challenge(token, identity);
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
    const current = await reloadIdentity();
    store.verified(token, current, challenge);
  } catch (error) {
    try { store.cancel(token, identity); } catch { /* already cancelled or expired */ }
    throw error;
  }
}

