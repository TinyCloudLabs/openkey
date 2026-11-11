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
