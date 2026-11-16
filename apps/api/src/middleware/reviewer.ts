import type { MiddlewareHandler } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { logReviewer } from '../log';
import { REVIEWER_MAX_SECONDS, captureReviewer, reviewerActive, reviewerForUser, reviewerForEmail } from '../services/reviewer-accounts';

const ROUTES = new Set([
  'GET /api/auth/get-session', 'POST /api/auth/sign-out',
  'POST /api/auth/sign-in/reviewer', 'POST /api/auth/sign-in/email-otp',
  'GET /api/auth/oauth2/authorize', 'POST /api/auth/oauth2/consent', 'POST /api/auth/oauth2/continue',
  'POST /api/auth/oauth2/token', 'GET /api/auth/oauth2/userinfo', 'POST /api/auth/oauth2/userinfo',
  'POST /api/auth/oauth2/introspect', 'POST /api/auth/oauth2/revoke',
  'GET /api/delegate/prepare', 'POST /api/delegate/prepare', 'POST /api/delegate', 'POST /api/delegate/complete',
]);

export function createReviewerRouteGuard(
  database: PrismaClient,
  resolve: (headers: Headers) => Promise<{ userId: string; sessionId: string | null } | null>,
): MiddlewareHandler {
  return async (c, next) => {
    const principal = await resolve(c.req.raw.headers);
    if (!principal) return next();
    const binding = await reviewerForUser(database, principal.userId);
    if (!binding) return next();
    const session = principal.sessionId
      ? await database.session.findUnique({ where: { id: principal.sessionId } }) : null;
    if (!reviewerActive(binding, session?.reviewerEpoch ?? null)
      || session?.userId !== binding.userId || session.expiresAt <= new Date()
      || session.createdAt.getTime() + REVIEWER_MAX_SECONDS * 1000 <= Date.now()
      || !ROUTES.has(`${c.req.method} ${c.req.path.replace(/\/$/, '')}`)) {
      return c.json({ error: 'Forbidden' }, 403);
    }
    captureReviewer(binding, session.id, session.createdAt.getTime() + 3600_000);
    await next();
  };
}

/** Includes provider refusals that run before the reviewer verifier hook. */
export function createReviewerAuthAudit(database: PrismaClient): MiddlewareHandler {
  return async (c, next) => {
    if (!['/api/auth/sign-in/reviewer', '/api/auth/sign-in/email-otp'].includes(c.req.path)) return next();
    let audited = c.req.path === '/api/auth/sign-in/reviewer';
    let store = 'unknown';
    try {
      const body = await c.req.raw.clone().json().catch(() => null);
      const binding = body?.email ? await reviewerForEmail(database, body.email) : null;
      if (binding) {
        audited = true;
        store = binding.store;
      }
      await next();
    } finally {
      if (audited) logReviewer('reviewer_sign_in', c.error || c.res.status >= 400 ? 'failed' : 'success', store);
    }
  };
}
