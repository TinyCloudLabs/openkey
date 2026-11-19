// TC-3232: the Terms gate on the OAuth provider's own routes. The provider's postLogin step (auth.ts) sends an
// authorize request to the Terms screen; these cover the routes that would otherwise get past it.
import type { MiddlewareHandler } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { hasAcceptedTerms, termsRequired } from '../services/terms';

const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' } as const;

/**
 * POST /oauth2/consent and /oauth2/continue. `continue {postLogin: true}` resumes an authorization without
 * asking postLogin again, so the session's account is checked here first. A request with no session is the
 * provider's to refuse.
 */
export function createTermsSessionGuard(
  database: Pick<PrismaClient, 'termsAcceptance'>,
  getSessionUserId: (headers: Headers) => Promise<string | null>,
): MiddlewareHandler {
  return async (c, next) => {
    if (c.req.method !== 'POST') return next();
    const userId = await getSessionUserId(c.req.raw.headers);
    if (userId && !await hasAcceptedTerms(database, userId)) return c.json(termsRequired(), 403, NO_STORE);
    await next();
  };
}

/**
 * /oauth2/userinfo answers for an access token until its own expiry. Like the locked-subject guard, this reads
 * the subject from the provider's successful answer and withdraws it until that account accepts.
 */
export function createTermsSubjectGuard(database: Pick<PrismaClient, 'termsAcceptance'>): MiddlewareHandler {
  return async (c, next) => {
    await next();
    if (c.res.status !== 200) return;
    let body: unknown;
    try {
      body = await c.res.clone().json();
    } catch {
      return;
    }
    const sub = body && typeof body === 'object' && 'sub' in body ? body.sub : undefined;
    if (typeof sub !== 'string' || !sub || await hasAcceptedTerms(database, sub)) return;
    (c as { res: Response | undefined }).res = undefined;
    c.res = Response.json(termsRequired(), { status: 403, headers: NO_STORE });
  };
}
