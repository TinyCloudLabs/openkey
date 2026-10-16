import type { Prisma, PrismaClient, PreparedHandoff as Row } from '@openkey/db';
import type { PreparedHandoffRecord, PreparedHandoffRequest, PreparedHandoffStore } from './prepared-handoff';

// Only service-validated request JSON is written to this table.
function fromRow(row: Row): PreparedHandoffRecord {
  return {
    ticketHash: row.ticketHash,
    cancelSecretHash: row.cancelSecretHash,
    request: row.request as unknown as PreparedHandoffRequest,
    ...(row.callback ? { callback: row.callback } : {}),
    state: row.state,
    expiresAt: row.expiresAt,
    requestedAt: row.requestedAt,
    requestIpHash: row.requestIpHash,
    status: row.status as PreparedHandoffRecord['status'],
    ownerId: row.ownerId,
    contextTokenHash: row.contextTokenHash,
    selectedKeyId: row.selectedKeyId,
  };
}

export function createPrismaPreparedHandoffStore(database: PrismaClient): PreparedHandoffStore {
  return {
    createLimited(record, since, limit) {
      // Serialize count and insert for one IP across API workers. PostgreSQL
      // releases this transaction-scoped lock on success or rollback.
      const lockId = BigInt.asIntN(64, BigInt(`0x${record.requestIpHash.slice(0, 16)}`));
      return database.$transaction(async (transaction) => {
        await transaction.$queryRaw`SELECT pg_advisory_xact_lock(${lockId})::text`;
        const count = await transaction.preparedHandoff.count({
          where: { requestIpHash: record.requestIpHash, requestedAt: { gte: since } },
        });
        if (count >= limit) return false;
        const request = record.request as unknown as Prisma.InputJsonValue;
        await transaction.preparedHandoff.create({ data: {
          ticketHash: record.ticketHash,
          cancelSecretHash: record.cancelSecretHash,
          request,
          callback: record.callback,
          state: record.state,
          expiresAt: record.expiresAt,
          requestedAt: record.requestedAt,
          requestIpHash: record.requestIpHash,
          status: record.status,
        } });
        return true;
      });
    },
    async find(ticketHash) {
      const row = await database.preparedHandoff.findUnique({ where: { ticketHash } });
      return row ? fromRow(row) : null;
    },
    async claim(ticketHash, ownerId, now) {
      const result = await database.preparedHandoff.updateMany({
        where: { ticketHash, ownerId: null, status: 'PENDING', expiresAt: { gt: now } },
        data: { ownerId },
      });
      return result.count === 1;
    },
    async bind(ticketHash, ownerId, contextTokenHash, selectedKeyId, now) {
      const result = await database.preparedHandoff.updateMany({
        where: { ticketHash, ownerId, contextTokenHash: null, status: 'PENDING', expiresAt: { gt: now } },
        data: { contextTokenHash, selectedKeyId },
      });
      return result.count === 1;
    },
    async reserve(ticketHash, ownerId, contextTokenHash, selectedKeyId, now) {
      const result = await database.preparedHandoff.updateMany({
        where: { ticketHash, ownerId, contextTokenHash, selectedKeyId, status: 'PENDING', expiresAt: { gt: now } },
        data: { status: 'CONSUMED' },
      });
      return result.count === 1;
    },
    async cancel(ticketHash, now, ownerId) {
      const result = await database.preparedHandoff.updateMany({
        where: { ticketHash, status: 'PENDING', expiresAt: { gt: now }, ...(ownerId !== undefined ? { ownerId } : {}) },
        data: { status: 'CANCELLED' },
      });
      return result.count === 1;
    },
  };
}
