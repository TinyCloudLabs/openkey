import { Hono, type Context, type MiddlewareHandler } from 'hono';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { PrismaClient } from '@openkey/db';
import type { TeeClient } from '@openkey/tee';
import type { SessionContext } from '../middleware/session';
import { requireOpenKeyOriginForBearer } from '../middleware/bearer-origin';
import { completeOrgRegistration, createOrgRegistrationHandler, type OrgRegistrationDependencies, type OrgRegistrationProof } from '../services/org-registration';
import {
  classifyOrgKeyMessage,
  findActiveOrgGrant,
  findOrgKeyForUser,
  isOrgKeyCustodyEnabled,
  issueOrgKeySignChallenge,
  listOrgKeysForUser,
  OrgKeyRefusal,
  ORG_KEY_ORIGINS,
  signOrgKeyMessage,
} from '../services/org-keys';

// auth.ts widens plugin inference; this is the existing Better Auth server-only JWT endpoint, not a signer.
interface ExistingJwtApi {
  signJWT(input: { body: { payload: OrgRegistrationProof } }): Promise<{ token: string }>;
}

const requireOrgKeyCustodyEnabled: MiddlewareHandler = async (c, next) => {
  if (!isOrgKeyCustodyEnabled()) return c.json({ error: 'Not found' }, 404);
  await next();
};

export type OrgKeysRouterDeps = {
  prisma: PrismaClient;
  tee: TeeClient;
  sessionMiddleware: MiddlewareHandler<SessionContext>;
  // Read per request so the relying-party settings track the environment.
  webauthn?: () => { rpID: string; origin: string };
  registration?: Partial<OrgRegistrationDependencies>;
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

// K1 D4.1: a missing Origin header, the opaque origin "null", and any origin
// outside ORG_KEY_ORIGINS are all refused. Returns the accepted origin or null.
function allowedOrigin(c: Context): string | null {
  const origin = c.req.header('origin');
  return origin !== undefined && ORG_KEY_ORIGINS.includes(origin) ? origin : null;
}

export function createOrgKeysRouter(deps: OrgKeysRouterDeps) {
  const { prisma, tee, sessionMiddleware } = deps;
  const webauthn = deps.webauthn ?? defaultWebauthn;
  const registerOrg = createOrgRegistrationHandler(prisma, tee, {
    fetch: deps.registration?.fetch,
    signProof: deps.registration?.signProof ?? (async (payload) => {
      const { auth } = await import('../auth');
      return (await (auth.api as typeof auth.api & ExistingJwtApi).signJWT({ body: { payload } })).token;
    }),
  });
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
    try {
      const relyingParty = deps.webauthn?.() ?? { rpID: 'openkey.so', origin: 'https://openkey.so' };
      const result = await registerOrg(await c.req.text(), {
        userId: c.get('user').id,
        sessionId: c.get('session').id,
        origin: c.req.header('origin'),
        rpID: relyingParty.rpID,
        expectedOrigin: relyingParty.origin,
      });
      if ('registrationChallenge' in result.body) return c.json(result.body, 200);
      const registration = await completeOrgRegistration(prisma, result.body.key.keyId, deps.registration?.fetch);
      return c.json({ key: result.body.key, registration }, result.status);
    } catch (error) {
      if (error instanceof OrgKeyRefusal) return c.json({ error: error.message, code: error.code }, error.status);
      throw error;
    }
  });

  // Issues the single-use signing challenge (K2a F2). The server records a
  // nonce bound to keyId, the caller's active grant, and the message digest.
  // The client signs over the derived challenge and returns the nonce to /sign.
  // K1 D4.1 order: active grant, origin, message classification.
  orgKeysRouter.post('/:keyId/sign-challenge', async (c) => {
    const user = c.get('user');
    const keyId = c.req.param('keyId');
    const body = await readJson<{ message?: unknown }>(c);
    if (!body || !isNonEmptyString(body.message)) return c.json({ error: 'message is required' }, 400);

    const grant = await findActiveOrgGrant(prisma, user.id, keyId);
    if (!grant) return c.json({ error: 'Forbidden', code: 'no_active_grant' }, 403);

    if (allowedOrigin(c) === null) return c.json({ error: 'Origin not allowed', code: 'origin_not_allowed' }, 403);

    const classification = classifyOrgKeyMessage(body.message);
    if (!classification.ok) return c.json({ error: 'Message refused', code: classification.refusal }, 403);

    const issued = await issueOrgKeySignChallenge(prisma, {
      userId: user.id,
      keyId,
      grantId: grant.grantId,
      message: body.message,
    });
    const passkeys = await prisma.passkey.findMany({
      where: { userId: user.id },
      select: { credentialID: true },
    });
    return c.json({
      nonce: issued.nonce,
      challenge: issued.challenge,
      expiresAt: issued.expiresAt.toISOString(),
      allowCredentials: passkeys.map((passkey) => ({ id: passkey.credentialID, type: 'public-key' })),
    });
  });

  // K1 D4.1 order: active grant (403), origin (403), message classification
  // (403), then the fresh passkey, single-use challenge, audit, and signature.
  // The classifier refuses every message until K4 defines the signable kinds,
  // so this route currently returns 403 for all messages.
  orgKeysRouter.post('/:keyId/sign', async (c) => {
    const user = c.get('user');
    const keyId = c.req.param('keyId');
    const body = await readJson<{ nonce?: unknown; message?: unknown; assertion?: unknown }>(c);
    if (!body || !isNonEmptyString(body.nonce) || !isNonEmptyString(body.message)) {
      return c.json({ error: 'nonce and message are required' }, 400);
    }
    if (!body.assertion || typeof body.assertion !== 'object') {
      return c.json({ error: 'assertion is required' }, 400);
    }

    const grant = await findActiveOrgGrant(prisma, user.id, keyId);
    if (!grant) return c.json({ error: 'Forbidden', code: 'no_active_grant' }, 403);

    const origin = allowedOrigin(c);
    if (origin === null) return c.json({ error: 'Origin not allowed', code: 'origin_not_allowed' }, 403);

    const classification = classifyOrgKeyMessage(body.message);
    if (!classification.ok) return c.json({ error: 'Message refused', code: classification.refusal }, 403);

    const relyingParty = webauthn();
    try {
      const result = await signOrgKeyMessage(prisma, tee, {
        userId: user.id,
        keyId,
        nonce: body.nonce,
        origin,
        message: body.message,
        messageKind: classification.kind,
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

