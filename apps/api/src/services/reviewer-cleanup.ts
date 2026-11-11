import { randomUUID } from 'node:crypto';
import type { Prisma, PrismaClient } from '@openkey/db';
import { logReviewerCleanup } from '../log';
import { REVIEWER_MAX_SECONDS, type ReviewerBinding } from './reviewer-accounts';

// Call under the binding lock, before releasing any writer artifact. Ordinary
// holds retain this high-water mark across epochs; only a fresh owner resets it.
export async function recordReviewerWriter(tx: Prisma.TransactionClient, binding: ReviewerBinding, expiresAt: Date) {
  if (!Number.isFinite(expiresAt.getTime()) || expiresAt <= new Date()
    || expiresAt.getTime() > Date.now() + REVIEWER_MAX_SECONDS * 1000) {
    throw new Error('Reviewer writer lifetime refused');
  }
  await tx.reviewerAccount.update({ where: { store: binding.store }, data: {
    writerExpiresAt: new Date(Math.max(expiresAt.getTime(), binding.writerExpiresAt?.getTime() ?? 0)),
  } });
}

// The key leaves ethereum_key, so generic signers cannot resolve it. This row
// deliberately survives deletion of the account. Never copy it back to a user.
export async function retireReviewerOwner(tx: Prisma.TransactionClient, binding: ReviewerBinding) {
  if (!binding.userId || !binding.keyId || !binding.spaceId || !binding.nodeHost) throw new Error('Reviewer retirement refused');
  const key = await tx.ethereumKey.findFirst({ where: { id: binding.keyId, userId: binding.userId } });
  if (!key?.sealedBlob) throw new Error('Reviewer retirement key unavailable');
  const retiredAt = new Date();
  const tombstoneUntil = new Date(Math.max(retiredAt.getTime(), binding.writerExpiresAt?.getTime() ?? 0));
  const boundExceeded = tombstoneUntil.getTime() > retiredAt.getTime() + REVIEWER_MAX_SECONDS * 1000;
  return tx.reviewerCleanup.create({ data: {
    id: randomUUID(), store: binding.store, ownerUserId: binding.userId,
    address: key.address, sealedBlob: key.sealedBlob, sealingContext: key.sealingContext,
    spaceId: binding.spaceId, nodeHost: binding.nodeHost, retiredAt, tombstoneUntil, boundExceeded,
  } });
}

type CleanupRow = Prisma.ReviewerCleanupGetPayload<Record<string, never>>;
// The adapter has no arbitrary-message or delegation method. It owns both
// enumeration and deletion; unknown pagination or SQL prefixes must fail.
export interface ReviewerCleanupAdapter {
  wipe(row: CleanupRow): Promise<void>;
  empty(row: CleanupRow): Promise<boolean>;
}

export async function runReviewerCleanup(database: PrismaClient, adapter: ReviewerCleanupAdapter) {
  const now = new Date();
  const due = await database.reviewerCleanup.findMany({
    where: { completedAt: null, retryAt: { lte: now }, OR: [{ leaseUntil: null }, { leaseUntil: { lte: now } }] },
    take: 10, orderBy: { retryAt: 'asc' },
  });
  for (const candidate of due) {
    const leaseUntil = new Date(Date.now() + 60_000);
    const claim = await database.reviewerCleanup.updateMany({ where: {
      id: candidate.id, completedAt: null, OR: [{ leaseUntil: null }, { leaseUntil: { lte: now } }],
    }, data: { leaseUntil, attempts: { increment: 1 } } });
    if (claim.count !== 1) continue;
    try {
      const row = await database.reviewerCleanup.findUniqueOrThrow({ where: { id: candidate.id } });
      if (row.boundExceeded || !row.sealedBlob) throw new Error('Reviewer cleanup retained');
      await adapter.wipe(row);
      const final = row.tombstoneUntil.getTime() <= Date.now();
      if (final && !await adapter.empty(row)) throw new Error('Reviewer cleanup is not empty');
      // A timed-out worker cannot destroy the key after another worker claims
      // the row. Failure/retry always retains the only cleanup authority.
      if (leaseUntil.getTime() <= Date.now()) throw new Error('Reviewer cleanup lease elapsed');
      await database.reviewerCleanup.updateMany({ where: { id: row.id, leaseUntil }, data: final ? {
        sealedBlob: null, completedAt: new Date(), leaseUntil: null,
      } : {
        initialWipedAt: new Date(), retryAt: row.tombstoneUntil, leaseUntil: null,
      } });
      logReviewerCleanup(final ? 'complete' : 'initial_wipe', row.spaceId);
    } catch {
      await database.reviewerCleanup.updateMany({ where: { id: candidate.id, leaseUntil }, data: {
        retryAt: new Date(Date.now() + 60_000), leaseUntil: null,
      } });
      logReviewerCleanup(candidate.boundExceeded ? 'bound_exceeded' : 'retry', candidate.spaceId);
    }
  }
}
