import type { Prisma } from '@openkey/db';
import { logError, withScheduledLogContext } from '../log';
import {
  DEVICE_AUTH_MAX_DELEGATION_TTL_MS,
  DEVICE_AUTH_RECOVERY_TTL_MS,
  DEVICE_AUTH_RESULT_SWEEP_BATCH_SIZE,
  type DeviceAuthorizationRecord,
  type DeviceAuthorizationStore,
  type DevicePermission,
} from './device-authorization';

/**
 * The `permissions` JSON column stores the requested scope, the owner's
 * reason, the requested lifetime, and (after approval) the approved subset
 * without a schema migration. Rows written before TC-539 hold a bare
 * permission array.
 */
type StoredDeviceScope = {
  version: 2;
  requested: DevicePermission[];
  approved?: DevicePermission[];
  reason?: string;
  ttlSeconds?: number;
};

type DeviceScope = Pick<DeviceAuthorizationRecord, 'permissions' | 'approvedPermissions' | 'reason' | 'delegationTtlSeconds'>;

function encodeScope(scope: DeviceScope): StoredDeviceScope {
  return {
    version: 2,
    requested: scope.permissions,
    ...(scope.approvedPermissions ? { approved: scope.approvedPermissions } : {}),
    ...(scope.reason ? { reason: scope.reason } : {}),
    ttlSeconds: scope.delegationTtlSeconds,
  };
}

function decodeScope(value: { permissions: unknown; delegationExpiresAt: Date; transactionExpiresAt: Date }): DeviceScope {
  // Older rows did not store the TTL; they were created with
  // delegationExpiresAt = transactionExpiresAt + TTL and allowed up to 90
  // days, so clamp to today's 30-day maximum.
  const derivedTtlSeconds = Math.min(
    DEVICE_AUTH_MAX_DELEGATION_TTL_MS / 1000,
    Math.floor((value.delegationExpiresAt.getTime() - value.transactionExpiresAt.getTime()) / 1000),
  );
  if (Array.isArray(value.permissions)) {
    return { permissions: value.permissions as DevicePermission[], delegationTtlSeconds: derivedTtlSeconds };
  }
  const scope = value.permissions as StoredDeviceScope;
  return {
    permissions: scope.requested,
    ...(scope.approved ? { approvedPermissions: scope.approved } : {}),
    ...(scope.reason ? { reason: scope.reason } : {}),
    delegationTtlSeconds: scope.ttlSeconds ?? derivedTtlSeconds,
  };
}

function fromDatabase(value: any): DeviceAuthorizationRecord {
  return {
    id: value.id,
    userCode: value.userCode,
    deviceSecretHash: value.deviceSecretHash,
    ...(value.ownerDid ? { ownerDid: value.ownerDid } : {}),
    codeChallenge: value.codeChallenge,
    sessionDid: value.sessionDid,
    publicJwk: value.publicJwk,
    relayPublicJwk: value.relayPublicJwk,
    ...decodeScope(value),
    nodeOrigin: value.nodeOrigin,
    shareOrigin: value.shareOrigin,
    delegationExpiresAt: value.delegationExpiresAt,
    transactionExpiresAt: value.transactionExpiresAt,
    requestedAt: value.requestedAt,
    requestIpHash: value.requestIpHash,
    nextPollAt: value.nextPollAt,
    pollIntervalSeconds: value.pollIntervalSeconds,
    status: value.status.toLowerCase(),
    ...(value.approvedByUserId ? { approvedByUserId: value.approvedByUserId } : {}),
    ...(value.encryptedResult ? { encryptedResult: value.encryptedResult } : {}),
    ...(value.consumedAt ? { consumedAt: value.consumedAt } : {}),
  };
}
function expiredRelayWhere(now: Date): Prisma.DeviceAuthorizationWhereInput {
  return {
    encryptedResult: { not: null },
    OR: [
      { delegationExpiresAt: { lte: now } },
      { status: 'APPROVED', transactionExpiresAt: { lte: now } },
      { status: 'CONSUMED', consumedAt: { lte: new Date(now.getTime() - DEVICE_AUTH_RECOVERY_TTL_MS) } },
    ],
  };
}

/** Runs immediately on startup, then independently of device traffic. Each
 * query is bounded; repeating full batches drains a backlog without overlap. */
export function startDeviceAuthorizationResultSweep(
  store: DeviceAuthorizationStore,
  now: () => Date = () => new Date(),
): { started: Promise<void>; stop: () => void } {
  let running = false;
  async function sweep(): Promise<void> {
    if (running) return;
    running = true;
    try {
      while (await store.purgeExpiredResults(now()) === DEVICE_AUTH_RESULT_SWEEP_BATCH_SIZE) { /* drain */ }
    } catch (error) {
      withScheduledLogContext(() => logError('error', 'device_authorization_result_cleanup_failed', error));
    } finally {
      running = false;
    }
  }
  const started = sweep();
  const timer = setInterval(sweep, 10_000);
  timer.unref();
  return { started, stop: () => clearInterval(timer) };
}

export function createPrismaDeviceAuthorizationStore(database: any): DeviceAuthorizationStore {
  return {
    async create(record) {
      const { permissions, approvedPermissions, reason, delegationTtlSeconds, ...columns } = record;
      await database.deviceAuthorization.create({
        data: {
          ...columns,
          status: record.status.toUpperCase(),
          permissions: encodeScope({ permissions, approvedPermissions, reason, delegationTtlSeconds }),
        },
      });
    },
    async findById(id) {
      const value = await database.deviceAuthorization.findUnique({ where: { id } });
      return value ? fromDatabase(value) : null;
    },
    async findByUserCode(userCode) {
      const value = await database.deviceAuthorization.findUnique({ where: { userCode } });
      return value ? fromDatabase(value) : null;
    },
    countRecentByIpHash(requestIpHash, since) {
      return database.deviceAuthorization.count({ where: { requestIpHash, requestedAt: { gte: since } } });
    },
    async updatePoll(id, nextPollAt) {
      await database.deviceAuthorization.updateMany({ where: { id }, data: { nextPollAt } });
    },
    async approve(id, input) {
      return database.$transaction(async (tx: any) => {
        const pending = { id, status: 'PENDING', transactionExpiresAt: { gt: new Date() } };
        const value = await tx.deviceAuthorization.findFirst({ where: pending });
        if (!value) return false;
        const result = await tx.deviceAuthorization.updateMany({
          where: pending,
          data: {
            status: 'APPROVED',
            approvedByUserId: input.userId,
            encryptedResult: input.encryptedResult,
            delegationExpiresAt: input.delegationExpiresAt,
            permissions: encodeScope({ ...decodeScope(value), approvedPermissions: input.approvedPermissions }),
          },
        });
        return result.count === 1;
      });
    },
    async deny(id, userId, now) {
      return database.$transaction(async (tx: Prisma.TransactionClient) => {
        const pending = { id, status: 'PENDING', transactionExpiresAt: { gt: now } };
        const record = await tx.deviceAuthorization.findFirst({ where: pending });
        if (!record?.ownerDid) return false;
        const address = /^did:pkh:eip155:1:(0x[0-9a-fA-F]{40})$/.exec(record.ownerDid)?.[1];
        if (!address) return false;
        const key = await tx.ethereumKey.findFirst({
          where: { userId, address: { equals: address, mode: 'insensitive' }, archivedAt: null },
          select: { id: true },
        });
        if (!key) return false;
        const result = await tx.deviceAuthorization.updateMany({
          where: { ...pending, ownerDid: record.ownerDid },
          data: { status: 'DENIED', approvedByUserId: userId },
        });
        return result.count === 1;
      });
    },
    async consumeApproved(id, now) {
      // The ciphertext must still be present at the same atomic transition.
      // A cleanup winner leaves no consumable row; return only the row that
      // UPDATE ... RETURNING actually wrote, never a prior SELECT snapshot.
      const [value] = await database.deviceAuthorization.updateManyAndReturn({
        where: {
          id, status: 'APPROVED', consumedAt: null, encryptedResult: { not: null },
          transactionExpiresAt: { gt: now }, delegationExpiresAt: { gt: now },
        },
        data: { status: 'CONSUMED', consumedAt: now },
      });
      return value ? fromDatabase(value) : null;
    },
    async purgeResult(id, now) {
      await database.deviceAuthorization.updateMany({
        where: { id, ...expiredRelayWhere(now) },
        data: { encryptedResult: null },
      });
    },
    async purgeExpiredResults(now) {
      const where = expiredRelayWhere(now);
      const rows: { id: string }[] = await database.deviceAuthorization.findMany({
        where, select: { id: true }, orderBy: { id: 'asc' }, take: DEVICE_AUTH_RESULT_SWEEP_BATCH_SIZE,
      });
      if (rows.length === 0) return 0;
      const result = await database.deviceAuthorization.updateMany({
        where: { ...where, id: { in: rows.map((row) => row.id) } },
        data: { encryptedResult: null },
      });
      return result.count;
    },
  };
}
