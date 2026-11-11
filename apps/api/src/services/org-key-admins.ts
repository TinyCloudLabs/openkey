import { nativeUserRetryAfter } from './native-delegation/user-rate-limit';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Prisma, PrismaClient } from '@openkey/db';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { findActiveOrgGrant, findActiveOrgKeyMetadata, OrgKeyRefusal } from './org-keys';
import { invitationEmail, matchesInvitationTarget, resolveInvitationIdentity } from './org-key-invitation-identity';
import { issueGrantChallenge, redeemGrantChallenge, type GrantActor, type GrantOperation } from './org-key-grant-challenge';

const refuse = () => { throw new OrgKeyRefusal(403, 'grant_forbidden', 'Forbidden'); };
const inviteLifetime = 7 * 24 * 60 * 60 * 1000;
export type InviteTarget = { email?: string; accountId?: string };
export type GrantAssertion = { nonce: string; assertion: AuthenticationResponseJSON };

async function lockKey(tx: Prisma.TransactionClient, keyId: string) {
  const keys = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM "ethereum_keys" WHERE id = ${keyId} AND custody = 'ORG' AND "archivedAt" IS NULL FOR UPDATE`;
  if (!keys.length) return refuse();
}
async function owner(tx: Prisma.TransactionClient, keyId: string, userId: string) {
  const grant = await tx.keyGrant.findFirst({ where: { keyId, role: 'OWNER', granteeUserId: userId, acceptedAt: { not: null }, revokedAt: null } });
  if (!grant) return refuse();
  return grant;
}
async function resolveTarget(tx: Prisma.TransactionClient, target: InviteTarget) {
  if (!!target.email === !!target.accountId) return refuse();
  if (target.email) {
    const email = invitationEmail(target.email);
    if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return refuse();
    return { invitedEmail: email, invitedUserId: null, encoded: `email:${email}` };
  }
  const account = await tx.user.findUnique({ where: { id: target.accountId! }, select: { id: true } });
  if (!account) return refuse();
  return { invitedEmail: null, invitedUserId: account.id, encoded: `account:${account.id}` };
}
function targetString(grant: { invitedEmail: string | null; invitedUserId: string | null }) {
  return grant.invitedEmail !== null ? `email:${grant.invitedEmail}` : `account:${grant.invitedUserId}`;
}

export type InvitationDelivery = (mail: { to: string; token: string; invitationId: string; ownerId: string; keyId: string; expiresAt: Date }) => Promise<void>;

export async function inviteAdmin(prisma: PrismaClient, actor: GrantActor, keyId: string, target: InviteTarget, proof?: GrantAssertion, deliver?: InvitationDelivery) {
  let mail: Parameters<InvitationDelivery>[0] | undefined;
  const result = await prisma.$transaction(async tx => {
    await lockKey(tx, keyId);
    await owner(tx, keyId, actor.userId);
    const recipient = await resolveTarget(tx, target);
    const existing = await tx.keyGrant.findFirst({ where: { keyId, acceptedAt: { not: null }, revokedAt: null,
      ...(recipient.invitedUserId ? { granteeUserId: recipient.invitedUserId } : { grantee: { email: { equals: recipient.invitedEmail!, mode: 'insensitive' } } }) } });
    if (!proof && existing) return refuse();
    const pending = await tx.keyGrant.count({ where: { keyId, role: 'ADMIN', acceptedAt: null, revokedAt: null, invitationExpiresAt: { gt: new Date() } } });
    if (!proof && pending >= 50) throw new OrgKeyRefusal(409, 'pending_invitation_limit', 'Forbidden');
    const stored = proof ? await tx.orgKeyGrantChallenge.findUnique({ where: { nonce: proof.nonce } }) : null;
    const grantId = stored?.grantId ?? randomUUID();
    const operation: GrantOperation = { purpose: 'invite', keyId, grantId, target: recipient.encoded, granteeDid: null };
    if (!proof) return { grantId, challenge: await issueGrantChallenge(tx, actor, operation) };
    const redeemed = await redeemGrantChallenge(tx, actor, operation, proof.nonce, proof.assertion);
    if (redeemed.retry) return redeemed.retry;
    if (existing) return refuse();
    if (pending >= 50) throw new OrgKeyRefusal(409, 'pending_invitation_limit', 'Forbidden');
    const senderRetry = nativeUserRetryAfter(`org-invite-sender:${actor.userId}`, 'org_invite_send');
    if (senderRetry) throw new OrgKeyRefusal(429, 'invitation_rate_limited', 'Forbidden', senderRetry);
    const recipientRetry = nativeUserRetryAfter(`org-invite-recipient:${recipient.encoded}`, 'org_invite_send');
    if (recipientRetry) throw new OrgKeyRefusal(429, 'invitation_rate_limited', 'Forbidden', recipientRetry);
    const previous = await tx.keyGrant.findMany({ where: { keyId, role: 'ADMIN', acceptedAt: null, revokedAt: null,
      invitedEmail: recipient.invitedEmail, invitedUserId: recipient.invitedUserId } });
    for (const old of previous) {
      await tx.keyGrant.update({ where: { id: old.id }, data: { revokedAt: new Date(), revokedByUserId: actor.userId } });
      await tx.keyGrantEvent.create({ data: { keyId, grantId: old.id, actorUserId: actor.userId, kind: 'cancel' } });
    }
    const expiresAt = new Date(Date.now() + inviteLifetime);
    const token = recipient.invitedEmail ? randomBytes(32).toString('base64url') : null;
    await tx.keyGrant.create({ data: { invitationTokenDigest: token ? tokenDigest(token) : null, id: grantId, keyId, role: 'ADMIN', invitedByUserId: actor.userId,
      invitedEmail: recipient.invitedEmail, invitedUserId: recipient.invitedUserId, invitationExpiresAt: expiresAt } });
    await tx.keyGrantEvent.create({ data: { keyId, grantId, actorUserId: actor.userId, kind: 'invited' } });
    if (token && recipient.invitedEmail) mail = { to: recipient.invitedEmail, token, invitationId: grantId, ownerId: actor.userId, keyId, expiresAt };
    const result = { invitationId: grantId, expiresAt: expiresAt.toISOString() };
    await redeemed.complete(result);
    return result;
  });
  if (mail) {
    try {
      if (!deliver) throw new Error('Email transport unavailable');
      await deliver(mail);
    } catch {
      await prisma.keyGrantEvent.create({ data: { keyId, grantId: mail.invitationId, actorUserId: actor.userId, kind: 'delivery-failed' } });
      return { ...result as object, delivery: 'failed' };
    }
  }
  return result;
}

function tokenDigest(token: string) { return createHash('sha256').update(token).digest('hex'); }
export async function maskedInvitation(prisma: PrismaClient, invitationId: string, token: string | undefined) {
  // The same indexed lookup and response for absent, invalid, and expired tokens.
  const digest = tokenDigest(token && /^[A-Za-z0-9_-]{43}$/.test(token) ? token : 'invalid');
  const grant = await prisma.keyGrant.findFirst({ where: { id: invitationId, invitationTokenDigest: digest, role: 'ADMIN', revokedAt: null, acceptedAt: null, invitationExpiresAt: { gt: new Date() } }, select: { invitedEmail: true } });
  if (!grant?.invitedEmail) return { maskedEmail: null };
  const [local, domain] = grant.invitedEmail.split('@');
  return { maskedEmail: `${local!.slice(0, 1)}•••@${domain}` };
}

async function recipientGrant(tx: Prisma.TransactionClient, actor: GrantActor, invitationId: string) {
  const user = await tx.user.findUnique({ where: { id: actor.userId }, select: { id: true, email: true, emailVerified: true } });
  if (!user) return refuse();
  const grant = await tx.keyGrant.findFirst({ where: { id: invitationId, role: 'ADMIN', OR: [
    { invitedUserId: user.id, invitedEmail: null },
    ...(user.emailVerified ? [{ invitedUserId: null, invitedEmail: invitationEmail(user.email) }] : []),
  ] } });
  if (!grant || !matchesInvitationTarget(grant, user)) return refuse();
  return grant;
}
export async function acceptAdmin(prisma: PrismaClient, actor: GrantActor, invitationId: string, proof?: GrantAssertion) {
  return prisma.$transaction(async tx => {
    const initial = await recipientGrant(tx, actor, invitationId);
    await lockKey(tx, initial.keyId);
    const grant = await recipientGrant(tx, actor, invitationId);
    const activeOwner = await tx.keyGrant.findFirst({ where: { keyId: grant.keyId, role: 'OWNER', acceptedAt: { not: null }, revokedAt: null, granteeUserId: { not: null } } });
    if (!activeOwner) return refuse();
    await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${actor.userId} FOR SHARE`;
    await tx.$queryRaw`SELECT id FROM "ethereum_keys" WHERE "userId" = ${actor.userId} AND custody = 'PERSONAL'
      AND "keyType" = 'MANAGED' AND "isCanonicalTinyCloud" = true AND "archivedAt" IS NULL FOR SHARE`;
    const granteeDid = await resolveInvitationIdentity(tx, actor.userId);
    const operation: GrantOperation = { purpose: 'accept', keyId: grant.keyId, grantId: grant.id, target: targetString(grant), granteeDid };
    if (proof) {
      const challenge = await tx.orgKeyGrantChallenge.findUnique({ where: { nonce: proof.nonce } });
      // Exact retry is allowed only for the same accepted person and binding.
      if (challenge?.consumedAt && grant.acceptedAt && !grant.revokedAt && grant.granteeUserId === actor.userId && grant.granteeDid === granteeDid) {
        return (await redeemGrantChallenge(tx, actor, operation, proof.nonce, proof.assertion)).retry;
      }
    }
    if (grant.acceptedAt || grant.revokedAt || !grant.invitationExpiresAt || grant.invitationExpiresAt.getTime() <= Date.now()) return refuse();
    if (!proof) return { challenge: await issueGrantChallenge(tx, actor, operation) };
    const redeemed = await redeemGrantChallenge(tx, actor, operation, proof.nonce, proof.assertion);
    if (grant.invitationExpiresAt.getTime() <= Date.now()) return refuse();
    const duplicate = await tx.keyGrant.findFirst({ where: { keyId: grant.keyId, granteeUserId: actor.userId, acceptedAt: { not: null }, revokedAt: null } });
    if (duplicate) return refuse();
    await tx.keyGrant.update({ where: { id: grant.id }, data: { granteeUserId: actor.userId, granteeDid, acceptedAt: new Date() } });
    await tx.keyGrantEvent.create({ data: { keyId: grant.keyId, grantId: grant.id, actorUserId: actor.userId, kind: 'accepted' } });
    const result = { keyId: grant.keyId };
    await redeemed.complete(result);
    return result;
  });
}

export async function adminRoster(prisma: PrismaClient, userId: string, keyId: string) {
  const actor = await findActiveOrgGrant(prisma, userId, keyId);
  if (!actor) return refuse();
  const grants = await prisma.keyGrant.findMany({
    where: { keyId, revokedAt: null, ...(actor.role === 'OWNER' ? {} : { OR: [{ id: actor.grantId }, { role: 'OWNER', acceptedAt: { not: null } }] }) },
    select: { grantee: { select: { name: true, email: true } }, id: true, role: true, granteeUserId: true, granteeDid: true, invitedEmail: actor.role === 'OWNER', invitedUserId: actor.role === 'OWNER', invitedAt: true, acceptedAt: true, invitationExpiresAt: true },
    orderBy: { createdAt: 'asc' },
  });
  const key = await findActiveOrgKeyMetadata(prisma, keyId);
  const registration = await prisma.orgKeyRegistration.findUnique({ where: { keyId }, select: { handle: true } });
  const events = actor.role === 'OWNER' ? await prisma.keyGrantEvent.findMany({ where: { keyId }, orderBy: { createdAt: 'desc' }, take: 30 }) : [];
  return { role: actor.role, grants, key, handle: registration?.handle ?? null, events };
}

export async function invitationSummary(prisma: PrismaClient, actor: GrantActor, invitationId: string) {
  return prisma.$transaction(async tx => {
    const grant = await recipientGrant(tx, actor, invitationId);
    if (grant.revokedAt) return { state: 'cancelled' as const };
    if (!grant.acceptedAt && (!grant.invitationExpiresAt || grant.invitationExpiresAt.getTime() <= Date.now())) return { state: 'expired' as const };
    const key = await findActiveOrgKeyMetadata(tx, grant.keyId);
    if (!key) return refuse();
    const registration = await tx.orgKeyRegistration.findUnique({ where: { keyId: grant.keyId }, select: { handle: true } });
    const inviter = grant.invitedByUserId ? await tx.user.findUnique({ where: { id: grant.invitedByUserId }, select: { name: true, email: true } }) : null;
    let personalDid: string | null;
    try { personalDid = await resolveInvitationIdentity(tx, actor.userId); }
    catch (error) { if (!(error instanceof OrgKeyRefusal) || error.code !== 'personal_identity_required') throw error; personalDid = null; }
    return { invitationId: grant.id, key, handle: registration?.handle ?? null, inviter, invitedEmail: grant.invitedEmail,
      personalDid, expiresAt: grant.invitationExpiresAt, accepted: grant.acceptedAt !== null };
  });
}

export async function revokeAdmin(prisma: PrismaClient, actor: GrantActor, keyId: string, grantId: string, proof?: GrantAssertion) {
  return prisma.$transaction(async tx => {
    await lockKey(tx, keyId);
    const [locked] = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM "key_grants" WHERE id = ${grantId} AND "keyId" = ${keyId} FOR UPDATE`;
    if (!locked) return refuse();
    const grant = await tx.keyGrant.findUniqueOrThrow({ where: { id: grantId } });
    if (grant.role !== 'ADMIN') return refuse();
    const actorGrant = await tx.keyGrant.findFirst({ where: { keyId, granteeUserId: actor.userId, acceptedAt: { not: null }, revokedAt: null } });
    const ownAcceptedGrant = grant.acceptedAt && grant.granteeUserId === actor.userId;
    if ((!actorGrant && !(proof && ownAcceptedGrant && grant.revokedAt)) || (actorGrant && actorGrant.role !== 'OWNER' && !ownAcceptedGrant)) return refuse();
    const purpose = !grant.acceptedAt ? 'cancel' : actorGrant?.role === 'OWNER' ? 'remove' : 'leave';
    const operation: GrantOperation = { purpose, keyId, grantId, target: targetString(grant), granteeDid: grant.granteeDid };
    if (!proof) {
      if (grant.revokedAt) return refuse();
      return { challenge: await issueGrantChallenge(tx, actor, operation) };
    }
    const redeemed = await redeemGrantChallenge(tx, actor, operation, proof.nonce, proof.assertion);
    if (redeemed.retry) return redeemed.retry;
    if (grant.revokedAt) return refuse();
    await tx.keyGrant.update({ where: { id: grantId }, data: { revokedAt: new Date(), revokedByUserId: actor.userId } });
    await tx.keyGrantEvent.create({ data: { keyId, grantId, actorUserId: actor.userId, kind: purpose } });
    const result = { keyId, grantId, purpose };
    await redeemed.complete(result);
    return result;
  });
}

export async function pendingInvitations(prisma: PrismaClient, userId: string) {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: userId }, select: { email: true, emailVerified: true } });
  return prisma.keyGrant.findMany({ where: { role: 'ADMIN', acceptedAt: null, revokedAt: null,
    invitationExpiresAt: { gt: new Date() }, key: { custody: 'ORG', archivedAt: null },
    OR: [{ invitedUserId: userId }, ...(user.emailVerified ? [{ invitedEmail: invitationEmail(user.email) }] : [])] },
    select: { id: true, invitationExpiresAt: true, key: { select: { orgKey: { select: { orgName: true } } } } } });
}
