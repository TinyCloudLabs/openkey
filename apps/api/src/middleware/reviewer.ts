import type { MiddlewareHandler } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { logReviewer } from '../log';
import { REVIEWER_MAX_SECONDS, captureReviewer, reviewerActive, reviewerForUser, reviewerForEmail } from '../services/reviewer-accounts';

const ROUTES = new Set([
  'POST /api/review-account/delete-intent', 'POST /api/review-account/delete',
  // TC-3232: with a Terms release configured, a reviewer must be able to read and accept the Terms.
  'GET /api/account/terms', 'POST /api/account/terms/accept',
  'GET /api/auth/get-session', 'POST /api/auth/sign-out',
  'POST /api/auth/sign-in/reviewer', 'POST /api/auth/sign-in/email-otp',
  'GET /api/auth/oauth2/authorize', 'GET /api/auth/oauth2/public-client',
  'POST /api/auth/oauth2/consent', 'POST /api/auth/oauth2/continue',
  'POST /api/auth/oauth2/token', 'GET /api/auth/oauth2/userinfo', 'POST /api/auth/oauth2/userinfo',
  'POST /api/auth/oauth2/introspect', 'POST /api/auth/oauth2/revoke',
  'GET /api/delegate/prepare', 'POST /api/delegate/prepare', 'POST /api/delegate', 'POST /api/delegate/complete',
]);

type Principal = { userId: string; sessionId: string | null };

/** `resolve` returns every principal the request carries: the cookie session and the bearer token. */
export function createReviewerRouteGuard(
  database: PrismaClient,
  resolve: (headers: Headers) => Promise<Principal[]>,
): MiddlewareHandler {
  return async (c, next) => {
    const principals = await resolve(c.req.raw.headers);
    const bindings = await Promise.all(principals.map((principal) => reviewerForUser(database, principal.userId)));
    if (!bindings.some(Boolean)) return next();
    const listed = ROUTES.has(`${c.req.method} ${c.req.path.replace(/\/$/, '')}`);
    const nativeConsentRoute = c.req.method === 'POST'
      && (/^\/api\/oauth\/tinycloud\/requests\/[^/]+\/(prepare|approve|deny)$/.test(c.req.path)
        || ['/api/auth/oauth2/tinycloud/renew', '/api/auth/oauth2/tinycloud/revoke'].includes(c.req.path));
    const hostedDelegate = c.req.path.startsWith('/api/delegate');
    let captured = false;
    for (const [index, principal] of principals.entries()) {
      // A reviewer credential beside any other account's credential is refused outright.
      const binding = bindings[index];
      const session = principal.sessionId
        ? await database.session.findUnique({ where: { id: principal.sessionId } }) : null;
      const allowed = binding?.store === 'apple' ? !hostedDelegate && (listed || nativeConsentRoute) : listed;
      if (!allowed || !binding || !reviewerActive(binding, session?.reviewerEpoch ?? null)
        || session?.userId !== binding.userId || session.expiresAt <= new Date()
        || session.createdAt.getTime() + REVIEWER_MAX_SECONDS * 1000 <= Date.now()) {
        return c.json({ error: 'Forbidden' }, 403);
      }
      if (c.req.path.replace(/\/$/, '') === '/api/auth/oauth2/public-client'
        && (c.req.path !== '/api/auth/oauth2/public-client' || c.req.queries('client_id')?.length !== 1
          || c.req.query('client_id') !== binding.clientId)) return c.json({ error: 'Forbidden' }, 403);
      if (!captured) captureReviewer(binding, session.id, session.createdAt.getTime() + 3600_000);
      captured = true;
    }
    await next();
  };
}

/** Includes provider refusals that run before the reviewer verifier hook. */
export function createReviewerAuthAudit(database: PrismaClient): MiddlewareHandler {
  return async (c, next) => {
    if (['/api/review-account/delete', '/api/auth/reviewer/delete', '/api/review-account/delete-intent', '/api/auth/reviewer/delete-intent'].includes(c.req.path)) {
      try { await next(); }
      finally {
        const failed = Boolean(c.error) || c.res.status >= 400;
        if (!c.req.path.endsWith('delete-intent') || failed) logReviewer('reviewer_admin',
          c.req.path.endsWith('delete-intent') ? 'delete_intent_failed' : failed ? 'delete_failed' : 'deleted', 'apple');
      }
      return;
    }
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
