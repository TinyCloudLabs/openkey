import { Hono, type Context, type MiddlewareHandler } from 'hono';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { createTeeClient, type TeeClient } from '@openkey/tee';
import { requireSession, type SessionContext } from '../middleware/session';
import { requireOpenKeyOriginForBearer } from '../middleware/bearer-origin';
import {
  createOrgKey,
  findActiveOrgGrant,
  findOrgKeyForUser,
  isOrgKeyCustodyEnabled,
  listOrgKeysForUser,
  OrgKeyRefusal,
  ORG_KEY_ORIGINS,
  orgKeySignChallenge,
  refuseOrgKeyMessage,
  signOrgKeyMessage,
} from '../services/org-keys';

const requireOrgKeyCustodyEnabled: MiddlewareHandler = async (c, next) => {
  if (!isOrgKeyCustodyEnabled()) return c.json({ error: 'Not found' }, 404);
  await next();
};

export type OrgKeysRouterDeps = {
  prisma: PrismaClient;
  tee: TeeClient;
  sessionMiddleware?: MiddlewareHandler<SessionContext>;
  // Read per request so the relying-party settings track the environment.
  webauthn?: () => { rpID: string; origin: string };
};

const defaultWebauthn = () => ({
  rpID: process.env.WEBAUTHN_RP_ID ?? '',
  origin: process.env.WEBAUTHN_ORIGIN ?? '',
});

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

async function readJson<T>(c: Context): Promise<T | null> {
  try {
    return await c.req.json<T>();
  } catch {
    return null;
  }
}

export function createOrgKeysRouter(deps: OrgKeysRouterDeps) {
  const { prisma, tee } = deps;
  const webauthn = deps.webauthn ?? defaultWebauthn;
  const sessionMiddleware = deps.sessionMiddleware ?? requireSession;
  const orgKeysRouter = new Hono<SessionContext>();
  orgKeysRouter.use('*', requireOrgKeyCustodyEnabled);
  // A bearer session token is accepted only from an OpenKey web origin (TC-688).
  orgKeysRouter.use('*', requireOpenKeyOriginForBearer);
  orgKeysRouter.use('*', sessionMiddleware);

  orgKeysRouter.get('/', async (c) => {
    const keys = await listOrgKeysForUser(prisma, c.get('user').id);
    return c.json({ keys });
  });

  orgKeysRouter.get('/:keyId', async (c) => {
    const key = await findOrgKeyForUser(prisma, c.get('user').id, c.req.param('keyId'));
    if (!key) return c.json({ error: 'Not found' }, 404);
    return c.json({ key });
  });

  orgKeysRouter.post('/', async (c) => {
    const body = await readJson<{ orgId?: unknown; orgName?: unknown; controllerDid?: unknown; label?: unknown }>(c);
    if (!body || !isNonEmptyString(body.orgId) || !isNonEmptyString(body.orgName) || !isNonEmptyString(body.controllerDid)) {
      return c.json({ error: 'orgId, orgName, and controllerDid are required' }, 400);
    }
    const label = isNonEmptyString(body.label) ? body.label : null;
    const created = await createOrgKey(prisma, tee, {
      userId: c.get('user').id,
      orgId: body.orgId,
      orgName: body.orgName,
      controllerDid: body.controllerDid,
      label,
    });
    return c.json({ key: created }, 201);
  });

  // Issues the passkey challenge for one signature. The challenge is derived
  // from keyId, the caller's grant, and the message digest (K1 D4.5), so it
  // needs no stored state; replay is blocked by the audit table.
  orgKeysRouter.post('/:keyId/sign-challenge', async (c) => {
    const user = c.get('user');
    const keyId = c.req.param('keyId');
    const body = await readJson<{ message?: unknown }>(c);
    if (!body || !isNonEmptyString(body.message)) return c.json({ error: 'message is required' }, 400);

    const grant = await findActiveOrgGrant(prisma, user.id, keyId);
    if (!grant) return c.json({ error: 'Forbidden', code: 'no_active_grant' }, 403);

    const refusal = refuseOrgKeyMessage(body.message);
    if (refusal) return c.json({ error: 'Message refused', code: refusal }, 403);

    const passkeys = await prisma.passkey.findMany({
      where: { userId: user.id },
      select: { credentialID: true },
    });
    return c.json({
      challenge: orgKeySignChallenge(keyId, grant.grantId, body.message).toString('base64url'),
      allowCredentials: passkeys.map((passkey) => ({ id: passkey.credentialID, type: 'public-key' })),
    });
  });

  // K1 D4.1 order: active grant (403), origin (403), D7 and classification
  // refusal (403), then the fresh passkey, audit, and signature. K2a has no
  // signable message kinds, so this route refuses every message; the signing
  // path is exercised through signOrgKeyMessage until K4 defines the kinds.
  orgKeysRouter.post('/:keyId/sign', async (c) => {
    const user = c.get('user');
    const keyId = c.req.param('keyId');
    const body = await readJson<{ message?: unknown; format?: unknown; assertion?: unknown }>(c);
    if (!body || !isNonEmptyString(body.message)) return c.json({ error: 'message is required' }, 400);
    if (!body.assertion || typeof body.assertion !== 'object') {
      return c.json({ error: 'assertion is required' }, 400);
    }

    const grant = await findActiveOrgGrant(prisma, user.id, keyId);
    if (!grant) return c.json({ error: 'Forbidden', code: 'no_active_grant' }, 403);

    const origin = c.req.header('origin') ?? '';
    if (!ORG_KEY_ORIGINS.includes(origin)) return c.json({ error: 'Origin not allowed', code: 'origin_not_allowed' }, 403);

    const refusal = refuseOrgKeyMessage(body.message);
    if (refusal) return c.json({ error: 'Message refused', code: refusal }, 403);

    const relyingParty = webauthn();
    try {
      const result = await signOrgKeyMessage(prisma, tee, {
        userId: user.id,
        keyId,
        grantId: grant.grantId,
        origin,
        message: body.message,
        format: body.format === 'raw' ? 'raw' : 'personal_sign',
        assertion: body.assertion as AuthenticationResponseJSON,
        rpID: relyingParty.rpID,
        expectedOrigin: relyingParty.origin,
      });
      return c.json({ signature: result.signature, address: result.address });
    } catch (error) {
      if (error instanceof OrgKeyRefusal) return c.json({ error: error.message, code: error.code }, error.status);
      throw error;
    }
  });

  return orgKeysRouter;
}

const prisma = createPrismaClient();
const tee = createTeeClient();
export const orgKeysRouter = createOrgKeysRouter({ prisma, tee });
