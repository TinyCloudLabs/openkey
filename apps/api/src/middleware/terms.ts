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
 * Marks a way out only when its JSON body says it is one: for a route that also serves account management.
 * Reads a copy of at most `maxBytes`; a larger or unparseable body is not marked and stays gated.
 */
export function allowBeforeTermsWhen(maxBytes: number, isWayOut: (body: Record<string, unknown>) => boolean) {
  return createMiddleware<SessionContext>(async (c, next) => {
    const body = await readJsonObject(c.req.raw, maxBytes);
    if (body && isWayOut(body)) c.set('leaving', true);
    await next();
  });
}

/** Consent bodies are an `accept` flag and the signed authorize query; anything larger is not a denial. */
const CONSENT_BODY_MAX_BYTES = 16 * 1024;

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
    if (options.allowDenial) {
      const body = await readJsonObject(c.req.raw, CONSENT_BODY_MAX_BYTES);
      if (body && body.accept !== true) return next();
    }
    const userId = await getSessionUserId(c.req.raw.headers);
    if (userId && !await hasAcceptedTerms(database, userId)) return c.json(termsRequired(), 403, NO_STORE);
    await next();
  };
}

/**
 * A JSON object body, read from a copy (the handler reads the original) and decoded as `Request.json()` does.
 * Undefined when the body is over `maxBytes`, is not JSON, or is not an object.
 */
async function readJsonObject(request: Request, maxBytes: number): Promise<Record<string, unknown> | undefined> {
  if (Number(request.headers.get('content-length')) > maxBytes) return undefined;
  const stream = request.clone().body;
  if (!stream) return undefined;
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
  try {
    const body: unknown = JSON.parse(new TextDecoder().decode(Buffer.concat(chunks)));
    return body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : undefined;
  } catch {
    return undefined;
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
