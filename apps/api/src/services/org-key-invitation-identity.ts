import { getAddress } from 'viem';
import type { PrismaClient } from '@openkey/db';
import { primaryKeyWhere } from './primary-key';
import { OrgKeyRefusal } from './org-keys';

export type InvitationTarget = { invitedEmail: string | null; invitedUserId: string | null };

export function invitationEmail(email: string): string {
  return email.trim().toLowerCase();
}

// TC-1518: verified OpenKey account email is sufficient in this version.
export function matchesInvitationTarget(
  target: InvitationTarget,
  user: { id: string; email: string; emailVerified: boolean },
): boolean {
  if (target.invitedUserId !== null) {
    return target.invitedEmail === null && target.invitedUserId === user.id;
  }
  return target.invitedEmail !== null && user.emailVerified
    && invitationEmail(target.invitedEmail) === invitationEmail(user.email);
}

export async function resolveInvitationIdentity(prisma: Pick<PrismaClient, 'ethereumKey'>, userId: string): Promise<string> {
  const key = await prisma.ethereumKey.findFirst({
    where: primaryKeyWhere(userId), select: { address: true },
  });
  if (!key) throw new OrgKeyRefusal(403, 'personal_identity_required', 'Forbidden');
  return `did:pkh:eip155:1:${getAddress(key.address)}`;
}
