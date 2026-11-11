import { createHash, randomBytes } from 'node:crypto';
import { verifyAuthenticationResponse, type AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { Prisma, PrismaClient } from '@openkey/db';
import { OrgKeyRefusal } from './org-keys';

export const ORG_KEY_GRANT_DOMAIN = 'openkey.org-key-grant/v1';
export type GrantActor = { userId: string; sessionId: string; origin: string; rpId: string };
export type GrantOperation = { purpose: 'invite' | 'accept' | 'cancel' | 'remove' | 'leave'; keyId: string; grantId: string; target: string; granteeDid: string | null };

function digest(parts: string[]): string {
  const hash = createHash('sha256');
  for (const part of parts) {
    const bytes = Buffer.from(part);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.digest('base64url');
}
export function grantOperationDigest(operation: GrantOperation): string {
  return digest([ORG_KEY_GRANT_DOMAIN, operation.purpose, operation.keyId, operation.grantId, operation.target, operation.granteeDid ?? '']);
}
export function grantPasskeyChallenge(actor: GrantActor, operationDigest: string, nonce: string): string {
  return digest([ORG_KEY_GRANT_DOMAIN, actor.userId, actor.sessionId, actor.origin, actor.rpId, operationDigest, nonce]);
}
const refuse = () => { throw new OrgKeyRefusal(403, 'grant_challenge_invalid', 'Forbidden'); };

export async function issueGrantChallenge(prisma: Pick<PrismaClient, 'orgKeyGrantChallenge' | 'passkey'>, actor: GrantActor, operation: GrantOperation) {
  const nonce = randomBytes(32).toString('base64url');
  const operationDigest = grantOperationDigest(operation);
  const expiresAt = new Date(Date.now() + 300_000);
  await prisma.orgKeyGrantChallenge.create({ data: {
    nonce, purpose: operation.purpose, keyId: operation.keyId, grantId: operation.grantId,
    userId: actor.userId, sessionId: actor.sessionId, origin: actor.origin, rpId: actor.rpId,
    operationDigest, granteeDid: operation.granteeDid, expiresAt,
  } });
  const passkeys = await prisma.passkey.findMany({ where: { userId: actor.userId }, select: { credentialID: true } });
  return { nonce, challenge: grantPasskeyChallenge(actor, operationDigest, nonce), expiresAt,
    allowCredentials: passkeys.map(p => ({ id: p.credentialID, type: 'public-key' as const })) };
}

// Call under the same transaction and authority locks as the grant mutation.
export async function redeemGrantChallenge(
  tx: Prisma.TransactionClient, actor: GrantActor, operation: GrantOperation,
  nonce: string, assertion: AuthenticationResponseJSON,
): Promise<{ retry: Prisma.JsonValue | null; complete: (result: Prisma.InputJsonValue) => Promise<void> }> {
  const operationDigest = grantOperationDigest(operation);
  const challenge = await tx.orgKeyGrantChallenge.findUnique({ where: { nonce } });
  if (!challenge || challenge.userId !== actor.userId || challenge.sessionId !== actor.sessionId
    || challenge.origin !== actor.origin || challenge.rpId !== actor.rpId
    || challenge.operationDigest !== operationDigest) return refuse();
  const session = await tx.session.findFirst({ where: { id: actor.sessionId, userId: actor.userId, expiresAt: { gt: new Date() } } });
  if (!session) return refuse();
  if (challenge.consumedAt) {
    if (!challenge.result) return refuse();
    return { retry: challenge.result, complete: async () => {} };
  }
  if (challenge.expiresAt.getTime() <= Date.now() || !assertion?.id) return refuse();
  const passkey = await tx.passkey.findFirst({ where: { userId: actor.userId, credentialID: assertion.id } });
  if (!passkey) return refuse();
  let newCounter: number;
  try {
    const verified = await verifyAuthenticationResponse({
      response: assertion, expectedChallenge: grantPasskeyChallenge(actor, operationDigest, nonce),
      expectedOrigin: actor.origin, expectedRPID: actor.rpId, requireUserVerification: true,
      credential: { id: passkey.credentialID, publicKey: Buffer.from(passkey.publicKey, 'base64'), counter: passkey.counter },
    });
    if (!verified.verified) return refuse();
    newCounter = verified.authenticationInfo.newCounter;
  } catch { return refuse(); }
  const consumed = await tx.orgKeyGrantChallenge.updateMany({
    where: { nonce, consumedAt: null, expiresAt: { gt: new Date() } }, data: { consumedAt: new Date() },
  });
  if (consumed.count !== 1) return refuse();
  const updated = await tx.passkey.updateMany({ where: { id: passkey.id, userId: actor.userId, counter: passkey.counter }, data: { counter: newCounter } });
  if (updated.count !== 1) return refuse();
  return { retry: null, complete: async result => {
    await tx.orgKeyGrantChallenge.update({ where: { nonce }, data: { result } });
  } };
}
