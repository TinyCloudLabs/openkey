import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { requireSession } from '../middleware/session';
import {
  DeviceAuthorizationError,
  DeviceAuthorizationService,
  type DeviceAuthorizationRecord,
  type DeviceAuthorizationStore,
} from '../services/device-authorization';

type DeviceAuthorizationVariables = {
  Variables: {
    user: { id: string };
  };
};

function fromDatabase(value: any): DeviceAuthorizationRecord {
  return {
    id: value.id,
    userCode: value.userCode,
    deviceSecretHash: value.deviceSecretHash,
    codeChallenge: value.codeChallenge,
    sessionDid: value.sessionDid,
    publicJwk: value.publicJwk,
    relayPublicJwk: value.relayPublicJwk,
    permissions: value.permissions,
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
      await database.deviceAuthorization.create({
        data: {
          ...record,
          status: record.status.toUpperCase(),
          publicJwk: record.publicJwk,
          permissions: record.permissions,
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
      const result = await database.deviceAuthorization.updateMany({
        where: { id, status: 'PENDING', transactionExpiresAt: { gt: new Date() } },
        data: {
          status: 'APPROVED',
          approvedByUserId: input.userId,
          encryptedResult: input.encryptedResult,
          delegationExpiresAt: input.delegationExpiresAt,
        },
      });
      return result.count === 1;
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

function routeError(c: any, error: unknown) {
  if (error instanceof DeviceAuthorizationError) {
    return c.json({ error: error.code, errorDescription: error.message }, error.status as any);
  }
  throw error;
}

export function createDeviceAuthorizationRouter(input: {
  service: DeviceAuthorizationService;
  sessionMiddleware?: typeof requireSession;
}): Hono<DeviceAuthorizationVariables> {
  const router = new Hono<DeviceAuthorizationVariables>();

  router.post('/', async (c) => {
    try {
      const body = await c.req.json();
      const forwarded = c.req.header('cf-connecting-ip') ?? c.req.header('x-forwarded-for')?.split(',')[0]?.trim();
      return c.json(await input.service.start(body, forwarded ?? 'unknown'), 201);
    } catch (error) {
      return routeError(c, error);
    }
  });

  router.post('/token', async (c) => {
    try {
      return c.json(await input.service.poll(await c.req.json()));
    } catch (error) {
      return routeError(c, error);
    }
  });

  router.get('/lookup', async (c) => {
    const value = await input.service.lookup(c.req.query('user_code') ?? '');
    if (!value) return c.json({ error: 'not_found' }, 404);
    return c.json({
      ...value,
      delegationExpiresAt: value.delegationExpiresAt.toISOString(),
      transactionExpiresAt: value.transactionExpiresAt.toISOString(),
      requestedAt: value.requestedAt.toISOString(),
      nextPollAt: value.nextPollAt.toISOString(),
    });
  });

  router.post('/:transactionId/approve', input.sessionMiddleware ?? requireSession as any, async (c) => {
    try {
      const user = c.get('user');
      await input.service.approve(c.req.param('transactionId'), user.id, await c.req.json());
      return c.json({ approved: true });
    } catch (error) {
      return routeError(c, error);
    }
  });

  return router;
}

function encryptionSecret(): string {
  const configured = process.env.DEVICE_AUTH_ENCRYPTION_SECRET ?? process.env.BETTER_AUTH_SECRET;
  if (configured) return configured;
  if (process.env.NODE_ENV === 'production' || process.env.TEE_MODE === 'production') {
    throw new Error('DEVICE_AUTH_ENCRYPTION_SECRET or BETTER_AUTH_SECRET is required');
  }
  return 'openkey-development-device-authorization-secret-only';
}

const prisma = createPrismaClient();
const verificationOrigin = process.env.WEBAUTHN_ORIGIN ?? 'http://localhost:5173';

export const deviceAuthorizationRouter = createDeviceAuthorizationRouter({
  service: new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(prisma), {
    verificationOrigin,
    encryptionSecret: encryptionSecret(),
  }),
});
