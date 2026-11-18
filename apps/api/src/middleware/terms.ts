// TC-3232: the Terms gate on the OAuth provider's own routes. The provider's postLogin step (auth.ts) sends an
// authorize request to the Terms screen; these cover the routes that would otherwise get past it.
import type { MiddlewareHandler } from 'hono';
import { createMiddleware } from 'hono/factory';
import type { PrismaClient } from '@openkey/db';
import type { SessionContext } from './session';
import { hasAcceptedTerms, termsRequired } from '../services/terms';

const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' } as const;

/**
 * Marks a way out: leaving never requires agreeing, so `requireSession` skips the Terms check on a route this
 * runs before. index.ts registers it for every way out ahead of the routers (Hono runs matching handlers in
 * registration order).
 */
export const allowBeforeTerms = createMiddleware<SessionContext>(async (c, next) => {
  c.set('leaving', true);
  await next();
});

/**
 * POST /oauth2/consent and /oauth2/continue. `continue {postLogin: true}` resumes an authorization without
 * asking postLogin again, so the session's account is checked here first. A request with no session is the
 * provider's to refuse. With `allowDenial` (consent only), a consent the user declines goes through: the
 * provider treats any `accept` other than `true` as a denial and answers access_denied, and leaving never
 * requires agreeing.
 */
export function createTermsSessionGuard(
  database: Pick<PrismaClient, 'termsAcceptance'>,
  getSessionUserId: (headers: Headers) => Promise<string | null>,
  options: { allowDenial?: boolean } = {},
): MiddlewareHandler {
  return async (c, next) => {
    if (c.req.method !== 'POST') return next();
    if (options.allowDenial && await isDenial(c.req.raw)) return next();
    const userId = await getSessionUserId(c.req.raw.headers);
    if (userId && !await hasAcceptedTerms(database, userId)) return c.json(termsRequired(), 403, NO_STORE);
    await next();
  };
}

/** A JSON body whose `accept` is anything but `true`. Read from a copy; the provider reads the original. */
async function isDenial(request: Request): Promise<boolean> {
  try {
    const body: unknown = await request.clone().json();
    return !!body && typeof body === 'object' && !Array.isArray(body) && (body as { accept?: unknown }).accept !== true;
  } catch {
    return false;
  }
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
