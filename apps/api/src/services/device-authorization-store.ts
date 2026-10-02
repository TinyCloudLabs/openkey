import {
  DEVICE_AUTH_MAX_DELEGATION_TTL_MS,
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
    async consumeApproved(id) {
      return database.$transaction(async (tx: any) => {
        const value = await tx.deviceAuthorization.findFirst({
          where: { id, status: 'APPROVED', consumedAt: null },
        });
        if (!value) return null;
        const updated = await tx.deviceAuthorization.updateMany({
          where: { id, status: 'APPROVED', consumedAt: null },
          data: {
            status: 'CONSUMED',
            consumedAt: new Date(),
            encryptedResult: null,
          },
        });
        if (updated.count !== 1) return null;
        return fromDatabase(value);
      });
    },
  };
}
