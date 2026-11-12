import type { Prisma } from '@openkey/db';

// Called under the route's user lock, after consuming its step-up proof.
export async function commitDeletionRequest(tx: Prisma.TransactionClient, userId: string): Promise<void> {
  await tx.accountDeletionJob.create({ data: { userId, progress: { owners: {} } } });
  await tx.user.update({ where: { id: userId }, data: { lockedAt: new Date() } });
  await tx.session.deleteMany({ where: { userId } });
  await tx.oauthAccessToken.deleteMany({ where: { userId } });
  await tx.oauthRefreshToken.deleteMany({ where: { userId } });
}
