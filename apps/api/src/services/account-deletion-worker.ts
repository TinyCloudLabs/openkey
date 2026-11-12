import type { PrismaClient } from '@openkey/db';
import { advanceDeletion, type DeletionAdapter, type DeletionJob } from './account-deletion-job';

type Progress = { owners?: Record<string, DeletionJob> };

// Adapter creation is worker-only: it may unseal the retained managed key,
// and must never create a TinyCloud session or an owner space.
export type DeletionAdapterFactory = (keyId: string) => Promise<DeletionAdapter>;

export async function runAccountDeletion(prisma: PrismaClient, id: string, adapter: DeletionAdapterFactory): Promise<void> {
  await prisma.$transaction(async tx => {
    const locks = await tx.$queryRaw<{ acquired: boolean }[]>`SELECT pg_try_advisory_xact_lock(hashtextextended(${id}, 2871)) AS acquired`;
    if (!locks[0]?.acquired) return;
    const row = await tx.accountDeletionJob.findUnique({ where: { id } });
    if (!row || row.state === 'complete') return;
    const progress = row.progress as Progress;
    progress.owners ??= {};
    const keys = await tx.ethereumKey.findMany({ where: { userId: row.userId, keyType: 'MANAGED' }, select: { id: true } });
    const save = async () => {
      await prisma.accountDeletionJob.update({ where: { id }, data: { progress: JSON.parse(JSON.stringify(progress)), nextAttemptAt: new Date(Date.now() + 60_000) } });
    };
    for (const key of keys) {
      const job = progress.owners[key.id] ??= { state: 'deletion_requested', hosts: {}, unreachableHosts: [] };
      try {
        await advanceDeletion(job, await adapter(key.id), {
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
    await tx.ethereumKey.deleteMany({ where: { userId: row.userId } });
    await tx.passkey.deleteMany({ where: { userId: row.userId } });
    await tx.session.deleteMany({ where: { userId: row.userId } });
    await tx.account.deleteMany({ where: { userId: row.userId } });
    await tx.verification.deleteMany({ where: { userId: row.userId } });
    await tx.user.delete({ where: { id: row.userId } });
    // Discard owner identifiers, hosts and space names on completion.
    await tx.accountDeletionJob.update({ where: { id }, data: { state: 'complete', progress: {} } });
  }, { timeout: 300_000 });
}
