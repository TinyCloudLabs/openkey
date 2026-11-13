import { pruneCompletedReviewTargets, type DurableResourceCompletion } from './account-deletion-review-completions';
import { randomUUID, createHash } from 'node:crypto';
import { validateReviewEvidence, type ReviewEvidence } from './account-deletion-review-evidence';
import { reviewJcs, validateReviewSnapshot } from './account-deletion-decision';
import type { Prisma, PrismaClient } from '@openkey/db';
import type { DeletionHostSnapshot } from './account-deletion-request';
import type { DeletionPreflight, DeletionReviewDecision } from './account-deletion-preflight';
import type { HostRow, ReviewDecisionProof } from './account-deletion-decision';
import { REVIEW_ALERTS, REVIEW_DEADLINE_MS, REVIEW_RECHECK_MS, reviewResolution } from './account-deletion-review-policy';

export interface DeletionReviewRuntime {
  completions(jobId: string, hosts: DeletionHostSnapshot): Promise<DurableResourceCompletion[]>;
  check(jobId: string, hosts: DeletionHostSnapshot): Promise<ReviewEvidence>;
  // The deadline implementation MUST use signDeadlineReviewDecisions, whose
  // request time and clock come only from the verified ledger/TEE provider.
  authorize(jobId: string, mode: 'operator' | 'deadline', snapshot: HostRow[], decision?: DeletionReviewDecision): Promise<ReviewDecisionProof[]>;
  // Resolves true only after ALL inventoried resources have durable completed
  // purges. Partial/accepted purges remain false, retaining owner keys.
  purge(jobId: string, fresh: DeletionPreflight, proofs: ReviewDecisionProof[] | undefined, resolution: { eventKey: string; snapshotHash: string }): Promise<boolean>;
  notify(jobId: string, eventKey: string): Promise<void>;
}

export async function reevaluateDeletionReview(prisma: PrismaClient, job: { id: string; userId: string; requestedAt: Date; progress: unknown }, leaseToken: string, runtime?: DeletionReviewRuntime): Promise<void> {
  const now = new Date();
  const snapshot = (job.progress as { hostSnapshot?: DeletionHostSnapshot }).hostSnapshot;
  const mutate = async (callback: (tx: Prisma.TransactionClient) => Promise<void>) => {
    await prisma.$transaction(async tx => {
      await tx.accountDeletionJob.update({ where: { id: job.id, leaseToken, leaseUntil: { gt: new Date() } }, data: { leaseUntil: new Date(Date.now() + 600_000) } });
      await callback(tx);
    });
  };
  const event = async (key: string, kind: string, summary: object, metadata?: { actor: string; decidedAt: Date; reason: string; disposition: string; expiresAt: Date }) => {
    const eventKey = `${job.id}:${key}`;
    await mutate(async tx => {
      await tx.accountDeletionReview.upsert({ where: { eventKey }, create: { jobId: job.id, eventKey, kind, summary: JSON.parse(JSON.stringify(summary)), ...metadata }, update: {} });
    });
    return eventKey;
  };
  const alert = async (key: string) => {
    const eventKey = await event(key, 'operator_alert', { code: key });
    const record = await prisma.accountDeletionReview.findUniqueOrThrow({ where: { eventKey } });
    if (record.deliveredAt) return record.deliveredAt;
    if (!runtime) return undefined;
    try {
      await runtime.notify(job.id, eventKey);
      const deliveredAt = new Date();
      await mutate(async tx => { await tx.accountDeletionReview.update({ where: { eventKey }, data: { deliveredAt } }); });
      return deliveredAt;
    } catch { return undefined; } // Durable undelivered alert remains retryable.
  };
  const next = [now.getTime() + REVIEW_RECHECK_MS, ...REVIEW_ALERTS.map(item => job.requestedAt.getTime() + item.offset), job.requestedAt.getTime() + REVIEW_DEADLINE_MS].filter(at => at > now.getTime());
  await mutate(async tx => {
    await tx.accountDeletionJob.update({ where: { id: job.id }, data: { nextAttemptAt: new Date(Math.min(...next)) } });
    await tx.user.update({ where: { id: job.userId }, data: { lockedAt: now } });
    await tx.session.deleteMany({ where: { userId: job.userId } });
    await tx.oauthAccessToken.deleteMany({ where: { userId: job.userId } });
    await tx.oauthRefreshToken.deleteMany({ where: { userId: job.userId } });
  });
  let alertsDelivered = true;
  for (const item of REVIEW_ALERTS) if (now.getTime() >= job.requestedAt.getTime() + item.offset) {
    const deliveredAt = await alert(`review-${item.key}`);
    if (!deliveredAt || deliveredAt.getTime() >= job.requestedAt.getTime() + REVIEW_DEADLINE_MS) alertsDelivered = false;
  }
  if (!runtime || !snapshot || snapshot.uncertain) return;
  const reconcileCompletions = async () => {
    const incoming = await runtime.completions(job.id, snapshot);
    let pending = true;
    await mutate(async tx => {
      const data = (await tx.accountDeletionJob.findUniqueOrThrow({ where: { id: job.id }, select: { progress: true } })).progress as { reviewTargets?: Record<string, string[]>; completedReviewTargets?: DurableResourceCompletion[] };
      if (!data.reviewTargets) return;
      const pruned = pruneCompletedReviewTargets(job.id, snapshot, data.reviewTargets, data.completedReviewTargets ?? [], incoming);
      pending = Object.values(pruned.targets).some(targets => targets.length > 0);
      await tx.accountDeletionJob.update({ where: { id: job.id }, data: { progress: JSON.parse(JSON.stringify({ ...data, reviewTargets: pruned.targets, completedReviewTargets: pruned.records })) } });
    });
    return !pending;
  };
  await reconcileCompletions();
  const check = await runtime.check(job.id, snapshot);
  const current = await prisma.accountDeletionJob.findUniqueOrThrow({ where: { id: job.id, leaseToken }, select: { progress: true } });
  const currentProgress = current.progress as { reviewTargets?: Record<string, string[]> };
  try { validateReviewEvidence(snapshot, currentProgress.reviewTargets, check); }
  catch {
    await mutate(async tx => { await tx.accountDeletionJob.update({ where: { id: job.id }, data: { progress: JSON.parse(JSON.stringify({ ...currentProgress, reviewPendingHosts: snapshot.configured.map(host => host.url) })) } }); });
    return;
  }
  await mutate(async tx => { await tx.accountDeletionJob.update({ where: { id: job.id }, data: { progress: JSON.parse(JSON.stringify({ ...currentProgress, reviewTargets: pruneCompletedReviewTargets(job.id, snapshot, check.fresh.resources, (currentProgress as { completedReviewTargets?: DurableResourceCompletion[] }).completedReviewTargets ?? [], []).targets, reviewPendingHosts: [] })) } }); });
  const latest = await prisma.accountDeletionReview.findFirst({ where: { jobId: job.id, kind: 'decision' }, orderBy: { createdAt: 'desc' } });
  const decision: DeletionReviewDecision | undefined = latest?.actor && latest.decidedAt && latest.reason && ['proceed', 'wait_for_re-encryption'].includes(latest.disposition ?? '') ? { actor: latest.actor, at: latest.decidedAt, expiresAt: latest.expiresAt ?? undefined, reason: latest.reason, disposition: latest.disposition as DeletionReviewDecision['disposition'] } : undefined;
  const reviewedSnapshot = (latest?.summary as { snapshot?: HostRow[] } | undefined)?.snapshot;
  let snapshotMatches = false;
  if (reviewedSnapshot) {
    try { validateReviewSnapshot(snapshot, reviewedSnapshot); snapshotMatches = true; } catch { /* Invalid review evidence cannot authorize purge. */ }
  }
  if (decision) decision.snapshot = reviewedSnapshot;
  if (decision?.disposition === 'proceed' && !snapshotMatches) await alert('review-snapshot-changed');
  const mode = reviewResolution(job.requestedAt, now, check.fresh, decision?.disposition === 'proceed' && !snapshotMatches ? undefined : decision);
  if (mode === 'pending') return;
  if (mode === 'deadline' && !alertsDelivered) {
    await alert('review-missed-predeadline-alert');
    return;
  }
  let proofs: ReviewDecisionProof[] | undefined;
  if (mode === 'zero') {
    if (check.snapshot.some(row => row[2] !== 0 || row[3].length !== 0 || row[4].some(target => target[1] !== 0))) return;

  } else {
    const proofScope = mode === 'operator' ? `operator-${latest!.id}` : 'deadline';
    const eventKey = `${job.id}:${proofScope}-proofs`;
    const existing = await prisma.accountDeletionReview.findUnique({ where: { eventKey } });
    if (existing) {
      proofs = (existing.summary as { proofs?: ReviewDecisionProof[] }).proofs;
    } else {
      try {
        proofs = await runtime.authorize(job.id, mode, check.snapshot, decision);
        if (!proofs.length || proofs.some(proof => proof.payload[4] !== job.id || proof.payload[8] !== 'proceed' || proof.payload[9] !== (mode === 'deadline' ? 'deadline' : decision!.actor))) throw new Error('Missing or mismatched review proofs');
        await event(`${proofScope}-proofs`, 'decision-proofs', { proofs, snapshot: check.snapshot }, { actor: mode === 'deadline' ? 'deadline' : decision!.actor, decidedAt: new Date((proofs[0]!.payload[10] as number) * 1000), reason: proofs[0]!.payload[11] as string, disposition: 'proceed', expiresAt: new Date((proofs[0]!.payload[14] as number) * 1000) });
      } catch {
        await alert('review-authorization-escalation');
        return;
      }
    }
    if (!proofs?.length || proofs.some(proof => proof.payload[4] !== job.id || proof.payload[8] !== 'proceed' || proof.payload[9] !== (mode === 'deadline' ? 'deadline' : decision!.actor) || typeof proof.payload[14] !== 'number' || proof.payload[14] <= Math.floor(Date.now() / 1000))) {
      await alert('review-authorization-escalation');
      return;
    }
  }
  const resolution = { eventKey: `${job.id}:resolution:${randomUUID()}`, snapshotHash: createHash('sha256').update(reviewJcs([1, check.snapshot])).digest('hex') };
  await mutate(async tx => {
    await tx.accountDeletionReview.create({ data: { jobId: job.id, eventKey: resolution.eventKey, kind: mode === 'zero' ? 'resolved: zero dependents' : 'purge-resolution', summary: { snapshot: JSON.parse(reviewJcs(check.snapshot)), snapshotHash: resolution.snapshotHash, mode } } });
    const latestProgress = (await tx.accountDeletionJob.findUniqueOrThrow({ where: { id: job.id }, select: { progress: true } })).progress as object;
    await tx.accountDeletionJob.update({ where: { id: job.id }, data: { progress: JSON.parse(JSON.stringify({ ...latestProgress, activeReviewResolution: resolution })) } });
  });
  try {
    const reportedComplete = await runtime.purge(job.id, check.fresh, proofs, resolution);
    const ledgerComplete = await reconcileCompletions();
    if (!reportedComplete || !ledgerComplete) return;
  } catch {
    if (mode === 'deadline') await alert('review-authorization-escalation');
    return;
  }
  // Resource completion precedes the existing space/key cleanup worker.
  await mutate(async tx => { await tx.accountDeletionJob.update({ where: { id: job.id }, data: { state: 'deletion_requested', nextAttemptAt: new Date() } }); });
}
