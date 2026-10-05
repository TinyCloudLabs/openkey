import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { requireSession } from '../middleware/session';
import { requireOpenKeyOriginForBearer } from '../middleware/bearer-origin';
import {
  DeviceAuthorizationError,
  DeviceAuthorizationService,
} from '../services/device-authorization';
import { createPrismaDeviceAuthorizationStore } from '../services/device-authorization-store';

type DeviceAuthorizationVariables = {
  Variables: {
    user: { id: string };
  };
};

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

  // Approval is a signed-in user action from the OpenKey /delegate page. A
  // bearer session token is accepted only from an OpenKey web origin (TC-688).
  router.post('/:transactionId/approve', requireOpenKeyOriginForBearer as any, input.sessionMiddleware ?? requireSession as any, async (c) => {
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

/** Shared with the delegate signing routes, which enforce device lifetimes. */
export const deviceAuthorizationService = new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(prisma), {
  verificationOrigin,
  encryptionSecret: encryptionSecret(),
});

export const deviceAuthorizationRouter = createDeviceAuthorizationRouter({ service: deviceAuthorizationService });
