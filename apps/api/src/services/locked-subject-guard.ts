// R9 (plan TC-1188 §2) for the provider's own access-token answers. A JWT
// access token has no stored row the lock filter in auth.ts could hide, so the
// provider's /oauth2/userinfo and /oauth2/introspect would still answer for a
// locked user until the token's own exp. This reads the subject from the
// provider's successful answer and withdraws it for a locked user.

import type { MiddlewareHandler } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { logError } from '../log';

const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' } as const;

export function createLockedSubjectGuard(database: Pick<PrismaClient, 'user'> & Partial<Pick<PrismaClient, 'session' | 'oauthConsent'>>): MiddlewareHandler {
  return async (c, next) => {
    await next();
    if (c.res.status !== 200) return;
    const introspect = new URL(c.req.url).pathname.endsWith('/oauth2/introspect');
    let sub: unknown;
    let claims: Record<string, unknown> = {};
    try {
      const body: unknown = await c.res.clone().json();
      if (body && typeof body === 'object') claims = body as Record<string, unknown>;
      sub = claims.sub;
    } catch {
      return;
    }
    if (typeof sub !== 'string' || !sub) return;
    let locked: boolean;
    try {
      const user = await database.user.findUnique({ where: { id: sub }, select: { lockedAt: true, reviewerHoldAt: true, reviewerBinding: true } });
      locked = Boolean(user?.lockedAt || user?.reviewerHoldAt);
      const binding = user?.reviewerBinding;
      if (introspect && binding && !locked) {
        const clientId = claims.client_id ?? claims.azp;
        const session = typeof claims.sid === 'string' ? await database.session?.findFirst({
          where: { id: claims.sid, userId: sub, reviewerEpoch: binding.installEpoch, expiresAt: { gt: new Date() } },
          select: { id: true },
        }) : null;
        const consent = typeof clientId === 'string' ? await database.oauthConsent?.findUnique({
          where: { userId_clientId: { userId: sub, clientId } }, select: { reviewerEpoch: true },
        }) : null;
        locked = !session || consent?.reviewerEpoch !== binding.installEpoch || clientId !== binding.clientId;
      }
    } catch (error) {
      logError('error', 'locked_subject_guard_failed', error);
      (c as { res: Response | undefined }).res = undefined;
      c.res = Response.json({ error: 'temporarily_unavailable' }, { status: 503, headers: { ...NO_STORE, 'Retry-After': '5' } });
      return;
    }
    if (!locked) return;
    (c as { res: Response | undefined }).res = undefined;
    c.res = introspect
      ? Response.json({ active: false }, { status: 200, headers: NO_STORE })
      : Response.json({ error: 'invalid_token', error_description: 'The access token is not active' }, {
        status: 401, headers: { ...NO_STORE, 'WWW-Authenticate': 'Bearer error="invalid_token"' },
      });
  };
}
