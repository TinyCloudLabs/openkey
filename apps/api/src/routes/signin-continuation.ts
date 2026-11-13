import { cors } from 'hono/cors';
import { requireSignInContinuation } from '../middleware/signin-continuation';
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { requireSession, type SessionContext } from '../middleware/session';
import { rejectNonBrowserControlRequest } from '../middleware/browser-control';
import { currentSignInIdentity, signInAssertionOptions, signInContinuations,
  verifySignInAssertion } from '../services/signin-assertion';

const prisma = createPrismaClient();
const rp = { rpID: process.env.WEBAUTHN_RP_ID!, origin: process.env.WEBAUTHN_ORIGIN! };
export const signInContinuationRouter = new Hono<SessionContext>();
signInContinuationRouter.use('*', requireSignInContinuation);
signInContinuationRouter.get('/capabilities', cors({ origin: '*', credentials: false }), c => c.json({ enabled: true, protocolVersion: 1 }));
signInContinuationRouter.use('*', requireSession);
signInContinuationRouter.use('*', async (c, next) => {
  const refused = rejectNonBrowserControlRequest(c);
  if (refused) return refused;
  await next();
});

for (const phase of ['options', 'verify', 'cancel'] as const) {
  signInContinuationRouter.post(`/${phase}`, async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body.requestId !== 'string' || !body.requestId || body.requestId.length > 256 ||
        typeof body.origin !== 'string' || typeof body.keyId !== 'string' ||
        !Number.isSafeInteger(body.chainId) || body.chainId <= 0) {
      return c.json({ code: 'invalid_signin_identity' }, 400);
    }
    try {
      const origin = new URL(body.origin);
      if (origin.origin !== body.origin || (origin.protocol !== 'https:' &&
          !(origin.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(origin.hostname)))) {
        return c.json({ code: 'invalid_signin_origin' }, 400);
      }
      const identity = await currentSignInIdentity(prisma, c.get('user').id, c.get('session').id,
        body.requestId, body.origin, body.keyId, body.chainId);
      if (phase === 'options') return c.json(await signInAssertionOptions(prisma, identity, rp));
      if (typeof body.token !== 'string') return c.json({ code: 'invalid_signin_token' }, 400);
      if (phase === 'cancel') {
        signInContinuations.cancel(body.token, identity);
        return c.json({ cancelled: true });
      }
      if (!body.response || typeof body.response.id !== 'string') return c.json({ code: 'invalid_signin_assertion' }, 400);
      await verifySignInAssertion(prisma, body.token, identity, body.response as AuthenticationResponseJSON, rp);
      // No cookie/session identifiers leave the OpenKey origin.
      const pinned = signInContinuations.identity(body.token, identity);
      return c.json({ token: body.token, requestId: pinned.requestId, keyId: pinned.keyId,
        keyType: pinned.keyType, address: pinned.address, chainId: pinned.chainId });
    } catch {
      return c.json({ code: 'signin_continuation_refused' }, 403);
    }
  });
}
