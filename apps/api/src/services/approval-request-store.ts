import type { PrismaClient } from '@openkey/db';
import { ApprovalResultError, type ApprovalRequestRecord, type ApprovalRequestStore } from './approval-results';

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
    async approve(id, result, now) {
      const saved = await database.approvalRequest.updateMany({
        where: { id, resultRef: null, expiresAt: { gt: now } }, data: result,
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
  };
}
