import { createHash } from 'node:crypto';
import type { Prisma, PrismaClient, PreparedHandoff as Row } from '@openkey/db';
import type { PreparedHandoffRecord, PreparedHandoffRequest, PreparedHandoffStore } from './prepared-handoff';

// Only service-validated request JSON is written to this table.
function fromRow(row: Row): PreparedHandoffRecord {
  return {
    ticketHash: row.ticketHash,
    cancelSecretHash: row.cancelSecretHash,
    nonceHash: row.nonceHash,
    request: row.request as unknown as PreparedHandoffRequest,
    ...(row.callback ? { callback: row.callback } : {}),
    state: row.state,
    expiresAt: row.expiresAt,
    requestedAt: row.requestedAt,
    status: row.status as PreparedHandoffRecord['status'],
    ownerId: row.ownerId,
    contextTokenHash: row.contextTokenHash,
    selectedKeyId: row.selectedKeyId,
  };
}

export function createPrismaPreparedHandoffStore(database: PrismaClient): PreparedHandoffStore {
  return {
    createLimited(record, since, limit) {
      // A transaction-scoped lock on the authenticated account serializes
      // admission across API workers; the nonce uniqueness index prevents
      // signing the same prepared session through a second handoff.
      const accountHash = createHash('sha256').update(`prepared-handoff-account\0${record.ownerId}`).digest('hex');
      const lockId = BigInt.asIntN(64, BigInt(`0x${accountHash.slice(0, 16)}`));
      return database.$transaction(async (transaction) => {
        await transaction.$queryRaw`SELECT pg_advisory_xact_lock(${lockId})::text`;
        const existing = await transaction.preparedHandoff.findFirst({
          where: { OR: [
            { ticketHash: record.ticketHash },
            { ownerId: record.ownerId, nonceHash: record.nonceHash },
          ] },
        });
        if (existing) return fromRow(existing);
        const count = await transaction.preparedHandoff.count({
          where: { ownerId: record.ownerId, requestedAt: { gte: since } },
        });
        if (count >= limit) return null;
        const request = record.request as unknown as Prisma.InputJsonValue;
        const created = await transaction.preparedHandoff.create({ data: {
          ticketHash: record.ticketHash,
          cancelSecretHash: record.cancelSecretHash,
          nonceHash: record.nonceHash,
          request,
          callback: record.callback,
          state: record.state,
          expiresAt: record.expiresAt,
          requestedAt: record.requestedAt,
          ownerId: record.ownerId,
          status: record.status,
        } });
        return fromRow(created);
      });
    },
    async find(ticketHash) {
      const row = await database.preparedHandoff.findUnique({ where: { ticketHash } });
      return row ? fromRow(row) : null;
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
