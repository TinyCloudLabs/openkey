import type { Prisma } from '@openkey/db';

export type DeletionHostSnapshot = {
  configured: { hostId: string; url: string }[];
  recorded: string[];
  uncertain: boolean;
};

// Called under the route's user lock, after consuming its step-up proof.
export async function commitDeletionRequest(tx: Prisma.TransactionClient, userId: string, configured: DeletionHostSnapshot['configured'] = []): Promise<void> {
  const [bootstrap, native, preparations] = await Promise.all([
    tx.tinyCloudBootstrapState.findMany({ where: { userId }, select: { tinycloudHost: true } }),
    tx.tinyCloudNativeGrant.findMany({ where: { userId }, select: { tinycloudHost: true } }),
    tx.tinyCloudNativePreparation.findMany({ where: { userId }, select: { tinycloudHost: true } }),
  ]);
  const recorded = [...new Set([
    process.env.TINYCLOUD_URL || 'https://node.tinycloud.xyz',
    ...bootstrap.map(row => row.tinycloudHost), ...native.map(row => row.tinycloudHost), ...preparations.map(row => row.tinycloudHost),
  ])];
  const hostSnapshot: DeletionHostSnapshot = { configured, recorded, uncertain: configured.length === 0 };
  await tx.accountDeletionJob.create({ data: { userId, progress: { owners: {}, hostSnapshot } } });
  await tx.user.update({ where: { id: userId }, data: { lockedAt: new Date() } });
  await tx.session.deleteMany({ where: { userId } });
  await tx.oauthAccessToken.deleteMany({ where: { userId } });
  await tx.oauthRefreshToken.deleteMany({ where: { userId } });
}
