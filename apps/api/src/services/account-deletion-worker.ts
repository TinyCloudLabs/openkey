import { randomUUID } from 'node:crypto';
import type { DeletionHostSnapshot } from './account-deletion-request';
import type { PrismaClient } from '@openkey/db';
import { advanceDeletion, type DeletionAdapter, type DeletionJob } from './account-deletion-job';

type Progress = { hostSnapshot?: DeletionHostSnapshot; owners?: Record<string, DeletionJob> };

// Adapter creation is worker-only: it may unseal the retained managed key,
// and must never create a TinyCloud session or an owner space.
export type DeletionAdapterFactory = (keyId: string, hosts: DeletionHostSnapshot) => Promise<DeletionAdapter>;

export async function runAccountDeletion(prisma: PrismaClient, id: string, adapter: DeletionAdapterFactory): Promise<void> {
  const leaseToken = randomUUID();
  const claimed = await prisma.accountDeletionJob.updateMany({ where: { id, state: 'deletion_requested', OR: [{ leaseUntil: null }, { leaseUntil: { lt: new Date() } }] }, data: { leaseToken, leaseUntil: new Date(Date.now() + 600_000) } });
  if (!claimed.count) return;
  try {
    const row = await prisma.accountDeletionJob.findUnique({ where: { id } });
    if (!row || row.state === 'complete') return;
    const progress = row.progress as Progress;
    progress.owners ??= {};
    if (!progress.hostSnapshot || progress.hostSnapshot.uncertain) return;
    const snapshot = progress.hostSnapshot;
    const keys = await prisma.ethereumKey.findMany({ where: { userId: row.userId, keyType: 'MANAGED' }, select: { id: true } });
    const save = async () => {
      await prisma.accountDeletionJob.update({ where: { id, leaseToken }, data: { leaseUntil: new Date(Date.now() + 600_000), progress: JSON.parse(JSON.stringify(progress)), nextAttemptAt: new Date(Date.now() + 60_000) } });
    };
    for (const key of keys) {
      const job = progress.owners[key.id] ??= { state: 'deletion_requested', hosts: {}, unreachableHosts: [] };
      try {
        const node = await adapter(key.id, snapshot);
        await advanceDeletion(job, {
          ...node,
          hosts: async () => snapshot.configured.map(host => host.url),
          recordedHosts: async () => snapshot.recorded,
        }, {
          save: async () => { await save(); },
          complete: async completed => { progress.owners![key.id] = completed; await save(); },
        });
      } catch {
        // No exception permits loss of keys or a successful deletion state.
        await save();
        return;
      }
    }
    if (keys.some(key => progress.owners![key.id]?.state !== 'complete')) return;
    await prisma.$transaction(async tx => {
      // The lease holder alone may perform the final atomic key removal.
      await tx.accountDeletionJob.update({ where: { id, leaseToken }, data: { state: 'complete', progress: {} } });
      await tx.ethereumKey.deleteMany({ where: { userId: row.userId } });
      await tx.passkey.deleteMany({ where: { userId: row.userId } });
      await tx.session.deleteMany({ where: { userId: row.userId } });
      await tx.account.deleteMany({ where: { userId: row.userId } });
      await tx.verification.deleteMany({ where: { userId: row.userId } });
      await tx.user.delete({ where: { id: row.userId } });
    });
  } finally {
    await prisma.accountDeletionJob.updateMany({ where: { id, leaseToken }, data: { leaseToken: null, leaseUntil: null } });
  }
}
