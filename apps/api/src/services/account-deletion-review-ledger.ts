import { reviewJcs, validateReviewSnapshot } from './account-deletion-decision';
import type { Prisma } from '@openkey/db';
import type { DeletionPreflight, DeletionReviewDecision } from './account-deletion-preflight';

// Caller owns the transaction/user lock. This records counts and keyed hashes,
// never owner addresses, network names, resource IDs or key material.
export async function recordDeletionPreflight(tx: Prisma.TransactionClient, jobId: string, userId: string, result: DeletionPreflight): Promise<void> {
  await tx.accountDeletionReview.create({ data: {
    jobId, kind: 'preflight', summary: { state: result.state, dependencies: result.dependencies, unavailableHostCount: result.unavailableHosts.length },
  } });
  const job = await tx.accountDeletionJob.findUniqueOrThrow({ where: { id: jobId }, select: { progress: true } });
  const progress = job.progress as { reviewTargets?: Record<string, string[]> };
  const reviewTargets = { ...progress.reviewTargets };
  for (const [host, resources] of Object.entries(result.resources)) if (result.inventoryComplete[host]) reviewTargets[host] = [...new Set([...(reviewTargets[host] ?? []), ...resources])];
  await tx.accountDeletionJob.update({ where: { id: jobId }, data: { progress: JSON.parse(JSON.stringify({ ...progress, reviewTargets })) } });
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
  if (decision.actor === 'deadline') throw new Error('Deadline requires its guarded signer');
  if (decision.disposition === 'proceed' && !decision.snapshot?.length) throw new Error('Missing reviewed dependency snapshot');
  if (decision.snapshot) {
    const job = await tx.accountDeletionJob.findUniqueOrThrow({ where: { id: jobId }, select: { progress: true } });
    const hosts = (job.progress as { hostSnapshot?: import('./account-deletion-request').DeletionHostSnapshot }).hostSnapshot;
    if (!hosts) throw new Error('Missing frozen review hosts');
    validateReviewSnapshot(hosts, decision.snapshot);
  }
  const expiresAt = decision.expiresAt ?? new Date(decision.at.getTime() + 172800_000);
  if (!Number.isFinite(expiresAt.getTime()) || expiresAt <= decision.at || expiresAt.getTime() - decision.at.getTime() > 172800_000) throw new Error('Invalid review expiry');
  await tx.accountDeletionReview.create({ data: {
    jobId, kind: 'decision', expiresAt, actor: decision.actor, decidedAt: decision.at,
    reason: decision.reason, disposition: decision.disposition, summary: decision.snapshot ? { snapshot: JSON.parse(reviewJcs(decision.snapshot)) } : {},
  } });
  await tx.accountDeletionJob.update({ where: { id: jobId }, data: { state: decision.disposition === 'wait_for_re-encryption' ? 'wait_for_re_encryption' : 'pending_review', nextAttemptAt: new Date() } });
}


// Privileged TEE-authority storage adapter: called only after verified request
// scope/time checks. The unique event key atomically reserves the signing
// record and nonce once per job; it grants no purge authority without a proof.
export async function claimDeadlineSigningRecord(prisma: import('@openkey/db').PrismaClient, jobId: string, requestId: string, nonce: string): Promise<boolean> {
  try {
    await prisma.$transaction(async tx => {
      await tx.accountDeletionJob.findUniqueOrThrow({ where: { id: jobId }, select: { id: true } });
      await tx.accountDeletionReview.create({ data: { jobId, eventKey: `${jobId}:deadline-attempt`, kind: 'deadline-attempt', actor: 'deadline', summary: { requestId, nonce } } });
    });
    return true;
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2002') return false;
    throw error;
  }
}
