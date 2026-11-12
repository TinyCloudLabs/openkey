import { getPrisma, type PrismaClient } from '@openkey/db';
import { runAccountDeletion, type DeletionAdapterFactory } from './account-deletion-worker';

// Replaced by the direct owner-PKH adapter once shared wire fixtures land.
const unavailableAdapter: DeletionAdapterFactory = async () => { throw new Error('Deletion transport unavailable'); };
export async function sweepAccountDeletions(prisma: PrismaClient = getPrisma(), adapter: DeletionAdapterFactory = unavailableAdapter): Promise<void> {
  const rows = await prisma.accountDeletionJob.findMany({
    where: { state: 'deletion_requested', nextAttemptAt: { lte: new Date() } },
    orderBy: { requestedAt: 'asc' }, take: 10, select: { id: true },
  });
  for (const row of rows) {
    try { await runAccountDeletion(prisma, row.id, adapter); }
    catch { /* A failed pass remains durable and eligible for retry. */ }
  }
}
let timer: ReturnType<typeof setInterval> | undefined;
export function startAccountDeletionSweep(): () => void {
  if (!timer) {
    let running = false;
    const tick = () => {
      if (running) return;
      running = true;
      void sweepAccountDeletions().catch(() => {}).finally(() => { running = false; });
    };
    timer = setInterval(tick, 60_000);
    timer.unref();
    tick();
  }
  return () => { if (timer) clearInterval(timer); timer = undefined; };
}
