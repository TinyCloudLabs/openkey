import { expect, test } from 'bun:test';
import { findActiveOrgGrant, findOrgKeyForUser, listOrgKeysForUser } from '../services/org-keys';
import { asPrisma, setupOrgKey } from './org-keys-fixtures';

test('pending grants are excluded while an accepted owner remains accessible', async () => {
  const { db, state, key } = await setupOrgKey();
  const prisma = asPrisma(db);
  state.grants.push({
    id: 'pending', keyId: key.keyId, role: 'ADMIN', granteeUserId: 'invitee',
    acceptedAt: null, revokedAt: null,
  });
  expect(await listOrgKeysForUser(prisma, 'invitee')).toEqual([]);
  expect(await findOrgKeyForUser(prisma, 'invitee', key.keyId)).toBeNull();
  expect(await findActiveOrgGrant(prisma, 'invitee', key.keyId)).toBeNull();
  expect(await findActiveOrgGrant(prisma, 'user_1', key.keyId)).toEqual({ grantId: key.grantId, role: 'OWNER' });
  expect(await listOrgKeysForUser(prisma, 'user_1')).toHaveLength(1);
});

test('fixture scalar filters and locked grant read exclude pending grants', async () => {
  const { db, state, key } = await setupOrgKey();
  const prisma = asPrisma(db);
  state.grants.push({
    id: 'pending', keyId: key.keyId, role: 'ADMIN', granteeUserId: 'invitee',
    acceptedAt: null, revokedAt: null,
  });
  expect(await prisma.keyGrant.findMany({ where: { acceptedAt: { not: null } } })).toHaveLength(1);
  expect(await prisma.keyGrant.findMany({ where: { role: { not: 'ADMIN' } } })).toHaveLength(1);
  const locked = (grantId: string, userId: string) => prisma.$queryRaw`
    SELECT id, role FROM "key_grants"
    WHERE id = ${grantId} AND "keyId" = ${key.keyId}
      AND "granteeUserId" = ${userId} AND "revokedAt" IS NULL
      AND "acceptedAt" IS NOT NULL FOR SHARE`;
  expect(await locked('pending', 'invitee')).toEqual([]);
  expect(await locked(key.grantId, 'user_1')).toEqual([{ id: key.grantId, role: 'OWNER' }]);
});

test('signing submits an accepted-only predicate in the locked SQL itself', async () => {
  const { issueOrgKeySignChallenge, signOrgKeyMessage } = await import('../services/org-keys');
  const { assertionFor, ORIGIN, RP_ID } = await import('./org-keys-fixtures');
  const ctx = await setupOrgKey();
  const prisma = asPrisma(ctx.db);
  const message = 'locked-grant-predicate';
  const issued = await issueOrgKeySignChallenge(prisma, {
    userId: 'user_1', keyId: ctx.key.keyId, grantId: ctx.key.grantId, message,
  });
  let submitted = '';
  ctx.db.$queryRaw = async (strings: TemplateStringsArray) => {
    submitted = strings.join('?');
    return [];
  };
  await expect(signOrgKeyMessage(prisma, ctx.tee, {
    userId: 'user_1', keyId: ctx.key.keyId, nonce: issued.nonce,
    message, messageKind: 'test-kind', origin: ORIGIN, expectedOrigin: ORIGIN, rpID: RP_ID,
    assertion: assertionFor(ctx.passkey, issued.challenge),
  })).rejects.toThrow('No active grant');
  expect(submitted).toMatch(/AND\s+"acceptedAt"\s+IS NOT NULL\s+FOR SHARE/);
});
