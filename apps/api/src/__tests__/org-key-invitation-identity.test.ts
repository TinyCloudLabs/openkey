import { expect, test } from 'bun:test';
import { getAddress } from 'viem';
import { matchesInvitationTarget, resolveInvitationIdentity } from '../services/org-key-invitation-identity';
import { asPrisma } from './org-keys-fixtures';

const user = { id: 'invitee', email: 'Person@example.test', emailVerified: true };
const emailTarget = { invitedEmail: ' person@EXAMPLE.test ', invitedUserId: null };

test('email acceptance requires verified matching email with sign-in normalization', () => {
  expect(matchesInvitationTarget(emailTarget, user)).toBe(true);
  expect(matchesInvitationTarget(emailTarget, { ...user, emailVerified: false })).toBe(false);
  expect(matchesInvitationTarget(emailTarget, { ...user, email: 'other@example.test' })).toBe(false);
  expect(matchesInvitationTarget(emailTarget, { ...user, email: 'person+tag@example.test' })).toBe(false);
  expect(matchesInvitationTarget(emailTarget, { ...user, email: 'per.son@example.test' })).toBe(false);
});

test('account invitation uses immutable account id, with exactly one target', () => {
  expect(matchesInvitationTarget({ invitedEmail: null, invitedUserId: user.id }, user)).toBe(true);
  expect(matchesInvitationTarget({ invitedEmail: null, invitedUserId: 'other' }, user)).toBe(false);
  expect(matchesInvitationTarget({ ...emailTarget, invitedUserId: user.id }, user)).toBe(false);
  expect(matchesInvitationTarget({ invitedEmail: null, invitedUserId: null }, user)).toBe(false);
});

test('identity uses only the authenticated account canonical personal managed key and round-trips EIP-55', async () => {
  const address = '0x52908400098527886e0f7030069857d2e4169ee7';
  const prisma = asPrisma({ ethereumKey: { findFirst: async ({ where }: { where: unknown }) => {
    expect(where).toEqual({ userId: user.id, custody: 'PERSONAL', keyType: 'MANAGED', archivedAt: null, isCanonicalTinyCloud: true });
    return { address };
  } } });
  const did = await resolveInvitationIdentity(prisma, user.id);
  expect(did).toBe(`did:pkh:eip155:1:${getAddress(address)}`);
  const [, method, namespace, chain, account] = did.split(':');
  expect(`${method}:${namespace}:${chain}`).toBe('pkh:eip155:1');
  expect(`did:pkh:eip155:1:${getAddress(account!)}`).toBe(did);
});

test('missing canonical personal identity cannot be replaced with an organisation identity', async () => {
  const prisma = asPrisma({ ethereumKey: { findFirst: async () => null } });
  await expect(resolveInvitationIdentity(prisma, user.id)).rejects.toThrow('Forbidden');
});
