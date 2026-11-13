import type { Prisma } from '@openkey/db';
import type { DeletionPreflight, DeletionReviewDecision } from './account-deletion-preflight';

// Caller owns the transaction/user lock. This records counts and keyed hashes,
// never owner addresses, network names, resource IDs or key material.
export async function recordDeletionPreflight(tx: Prisma.TransactionClient, jobId: string, userId: string, result: DeletionPreflight): Promise<void> {
  await tx.accountDeletionReview.create({ data: {
    jobId, kind: 'preflight', summary: { state: result.state, dependencies: result.dependencies, unavailableHostCount: result.unavailableHosts.length },
  } });
  if (result.state !== 'pending_review') return;
  await tx.accountDeletionJob.update({ where: { id: jobId }, data: { state: 'pending_review' } });
  await tx.user.update({ where: { id: userId }, data: { lockedAt: new Date() } });
  await tx.session.deleteMany({ where: { userId } });
  await tx.oauthAccessToken.deleteMany({ where: { userId } });
  await tx.oauthRefreshToken.deleteMany({ where: { userId } });
}

// This records a human decision; it grants no permission to skip fresh checks.
export async function recordDeletionReviewDecision(tx: Prisma.TransactionClient, jobId: string, decision: DeletionReviewDecision): Promise<void> {
  if (!decision.actor.trim() || !decision.reason.trim() || !Number.isFinite(decision.at.getTime()) || !['proceed', 'wait_for_re-encryption'].includes(decision.disposition)) throw new Error('Incomplete deletion decision');
  await tx.accountDeletionReview.create({ data: {
    jobId, kind: 'decision', actor: decision.actor, decidedAt: decision.at,
    reason: decision.reason, disposition: decision.disposition, summary: {},
  } });
}
