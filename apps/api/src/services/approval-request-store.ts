import { Prisma, type PrismaClient } from '@openkey/db';
import { APPROVAL_CLAIM_LEASE_MS, ApprovalResultError, type ApprovalRequestRecord, type ApprovalRequestStore } from './approval-results';

const leaseStart = (now: Date) => new Date(now.getTime() - APPROVAL_CLAIM_LEASE_MS);

/** How often admission also clears the renewal steps of requests that expired unapproved (TC-2933). */
const STALE_RENEWAL_SWEEP_MS = 10 * 60_000;

/** Rolls back a leased approval whose lease reservation can't be confirmed (TC-2946). */
class UnreservedLease extends Error {}

// The saved renewal steps (TC-2933) hold the approved grant and the signed lease. They are only needed until
// the result is saved: every write that settles a request (approve, deny, ACK) clears them, and admission
// periodically clears them from requests that expired without a result.
export function createPrismaApprovalRequestStore(database: PrismaClient): ApprovalRequestStore {
  let lastStaleSweep = 0;
  async function clearStaleRenewals(now: Date): Promise<void> {
    if (now.getTime() - lastStaleSweep < STALE_RENEWAL_SWEEP_MS) return;
    lastStaleSweep = now.getTime();
    await database.approvalRequest.updateMany({
      where: { resultRef: null, expiresAt: { lt: leaseStart(now) }, NOT: [{ renewal: { equals: Prisma.DbNull } }] },
      data: { renewal: Prisma.DbNull },
    });
  }
  return {
    async register(record) {
      // A new request has no renewal steps; they are only ever written by `saveRenewal`.
      const { renewal: _renewal, ...fields } = record;
      const saved = await database.approvalRequest.upsert({ where: { id: record.id }, create: { ...fields, request: record.request as object }, update: {} });
      if (saved.bodyCid !== record.bodyCid || saved.issuer !== record.issuer || saved.expiresAt.getTime() !== record.expiresAt.getTime()) {
        throw new ApprovalResultError('request_binding', 'Immutable approval request binding changed', 409);
      }
      return saved as unknown as ApprovalRequestRecord;
    },
    async findById(id) {
      return await database.approvalRequest.findUnique({ where: { id } }) as unknown as ApprovalRequestRecord | null;
    },
    async findByResultRef(resultRef) {
      return await database.approvalRequest.findUnique({ where: { resultRef } }) as unknown as ApprovalRequestRecord | null;
    },
    async admit(id, now) {
      const saved = await database.approvalRequest.updateMany({
        where: { id, resultRef: null, deniedAt: null, expiresAt: { gt: now }, OR: [{ approvingAt: null }, { approvingAt: { lte: leaseStart(now) } }] },
        data: { approvingAt: now },
      });
      await clearStaleRenewals(now);
      return saved.count === 1 ? now : null;
    },
    async release(id, marker) {
      await database.approvalRequest.updateMany({ where: { id, resultRef: null, approvingAt: marker }, data: { approvingAt: null } });
    },
    async approve(id, result, now, marker) {
      // One conditional write settles it. Admitted: this exact marker (a deny or a re-admission after a lapse has replaced or voided it), on a request no more than one lease past its deadline.
      // Not admitted: the request must be unexpired and no other approval live.
      const { lease, ...fields } = result;
      const where = marker
        ? { id, resultRef: null, deniedAt: null, approvingAt: marker, expiresAt: { gt: leaseStart(now) } }
        : { id, resultRef: null, deniedAt: null, expiresAt: { gt: now }, OR: [{ approvingAt: null }, { approvingAt: { lte: leaseStart(now) } }] };
      const data = { ...fields, renewal: Prisma.DbNull };
      if (!lease) return (await database.approvalRequest.updateMany({ where, data })).count === 1;
      // A leased approval confirms its lease record in the same write, and only when this save wins. The record was
      // reserved before the node admitted the lease (TC-2946); a reservation that is missing, names another lease, or
      // was settled meanwhile (stopped, or never admitted) approves nothing.
      try {
        return await database.$transaction(async (tx) => {
          if ((await tx.approvalRequest.updateMany({ where, data })).count !== 1) return false;
          const confirmed = await tx.renewalLease.updateMany({
            where: {
              leaseCid: lease.leaseCid, userId: lease.userId, approvalRequestId: lease.approvalRequestId, ownerDid: lease.ownerDid,
              originalCid: lease.originalCid, nodeOrigin: lease.nodeOrigin, revokedAt: null, neverAdmittedAt: null,
            },
            data: { admittedAt: now, leaseAuthorization: null, sessionId: lease.sessionId },
          });
          if (confirmed.count !== 1) throw new UnreservedLease();
          return true;
        });
      } catch (error) {
        if (error instanceof UnreservedLease) return false;
        throw error;
      }
    },
    async saveRenewal(id, stage, marker) {
      const saved = await database.approvalRequest.updateMany({
        where: { id, resultRef: null, deniedAt: null, approvingAt: marker },
        data: { renewal: stage as object },
      });
      return saved.count === 1;
    },
    async acknowledge(resultRef, ackId, now) {
      return database.$transaction(async (tx) => {
        const saved = await tx.approvalRequest.updateMany({
          where: { resultRef, resultExpiresAt: { gt: now }, OR: [{ ackId: null }, { ackId }] },
          data: { ackId, acknowledgedAt: now, encryptedResult: null, renewal: Prisma.DbNull },
        });
        if (saved.count !== 1) return null;
        return await tx.approvalRequest.findUnique({ where: { resultRef } }) as unknown as ApprovalRequestRecord;
      });
    },
    async deny(id, now) {
      const saved = await database.approvalRequest.updateMany({
        where: { id, resultRef: null, deniedAt: null, expiresAt: { gt: now }, OR: [{ approvingAt: null }, { approvingAt: { lte: leaseStart(now) } }] }, data: { deniedAt: now, renewal: Prisma.DbNull },
      });
      return saved.count === 1;
    },
  };
}
