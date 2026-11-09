import type { PrismaClient } from '@openkey/db';
import { APPROVAL_CLAIM_LEASE_MS, ApprovalResultError, type ApprovalRequestRecord, type ApprovalRequestStore } from './approval-results';

const leaseStart = (now: Date) => new Date(now.getTime() - APPROVAL_CLAIM_LEASE_MS);

export function createPrismaApprovalRequestStore(database: PrismaClient): ApprovalRequestStore {
  return {
    async register(record) {
      const saved = await database.approvalRequest.upsert({ where: { id: record.id }, create: { ...record, request: record.request as object }, update: {} });
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
      return saved.count === 1 ? now : null;
    },
    async release(id, marker) {
      await database.approvalRequest.updateMany({ where: { id, resultRef: null, approvingAt: marker }, data: { approvingAt: null } });
    },
    async approve(id, result, now, marker) {
      // One conditional write settles it. Admitted: this exact marker, within its lease, on a request no more than one lease past its deadline.
      // Not admitted: the request must be unexpired and no other approval live.
      if (marker && marker.getTime() <= leaseStart(now).getTime()) return false;
      const saved = await database.approvalRequest.updateMany({
        where: marker
          ? { id, resultRef: null, deniedAt: null, approvingAt: marker, expiresAt: { gt: leaseStart(now) } }
          : { id, resultRef: null, deniedAt: null, expiresAt: { gt: now }, OR: [{ approvingAt: null }, { approvingAt: { lte: leaseStart(now) } }] },
        data: result,
      });
      return saved.count === 1;
    },
    async acknowledge(resultRef, ackId, now) {
      return database.$transaction(async (tx) => {
        const saved = await tx.approvalRequest.updateMany({
          where: { resultRef, resultExpiresAt: { gt: now }, OR: [{ ackId: null }, { ackId }] },
          data: { ackId, acknowledgedAt: now, encryptedResult: null },
        });
        if (saved.count !== 1) return null;
        return await tx.approvalRequest.findUnique({ where: { resultRef } }) as unknown as ApprovalRequestRecord;
      });
    },
    async deny(id, now) {
      const saved = await database.approvalRequest.updateMany({
        where: { id, resultRef: null, deniedAt: null, expiresAt: { gt: now }, OR: [{ approvingAt: null }, { approvingAt: { lte: leaseStart(now) } }] }, data: { deniedAt: now },
      });
      return saved.count === 1;
    },
  };
}
