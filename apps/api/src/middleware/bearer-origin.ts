import { createMiddleware } from 'hono/factory';
import { isAccountOriginAllowed, resolveOriginPolicy } from '../origin-policy';

/**
 * OpenKey's own embedded widgets authenticate to key and account routes with a
 * bearer session token because third-party iframes cannot rely on cookies.
 * They always run on an OpenKey web origin. A bearer credential presented
 * from any other origin, or with no Origin at all (a server-side caller), is
 * refused before the session is resolved (TC-688).
 *
 * This is defence in depth: a server holding a leaked token can forge the
 * Origin header. The primary control is that OpenKey never hands its session
 * token to an embedding page.
 */
export function bearerFromOpenKeyOriginError(
  authorization: string | undefined,
  origin: string | undefined,
): string | null {
  if (!authorization) return null;
  const allowed = resolveOriginPolicy('http://localhost:5173,http://localhost:3000');
  if (origin && allowed.includes(origin)) return null;
  return 'Bearer session tokens are accepted only from OpenKey';
}

export function bearerFromAccountOriginError(
  authorization: string | undefined,
  origin: string | undefined,
): string | null {
  if (!authorization) return null;
  if (isAccountOriginAllowed(origin, 'http://localhost:5173,http://localhost:3000')) return null;
  return 'Bearer session tokens are accepted only from OpenKey';
}

export const requireAccountOriginForBearer = createMiddleware(async (c, next) => {
  const authorization = c.req.header('authorization');
  const origin = c.req.header('origin');
  const error = origin !== undefined
    ? (isAccountOriginAllowed(origin, 'http://localhost:5173,http://localhost:3000')
      ? null
      : 'Requests are accepted only from the OpenKey account origin')
    : bearerFromAccountOriginError(authorization, origin);
  if (error) return c.json({ error }, 403);
  await next();
});
// Keep protocol, sign-in and session-read endpoints outside this account-management list.
const sensitiveAuthEndpoints: Record<string, string> = {
  '/passkey/generate-register-options': 'GET',
  '/passkey/verify-registration': 'POST',
  '/passkey/list-user-passkeys': 'GET',
  '/passkey/update-passkey': 'POST',
  '/passkey/delete-passkey': 'POST',
  '/update-user': 'POST',
  '/revoke-session': 'POST',
  '/revoke-sessions': 'POST',
  '/revoke-other-sessions': 'POST',
  '/list-sessions': 'GET',
  '/list-accounts': 'GET',
  '/link-social': 'POST',
  '/unlink-account': 'POST',
  '/change-email': 'POST',
  '/email-otp/request-email-change': 'POST',
  '/email-otp/change-email': 'POST',
  '/change-password': 'POST',
  '/delete-user': 'POST',
  '/oauth2/get-consent': 'GET',
  '/oauth2/get-consents': 'GET',
  '/oauth2/update-consent': 'POST',
  '/oauth2/delete-consent': 'POST',
  '/oauth2/consent': 'POST',
};

export const requireAccountOriginForSensitiveAuth = createMiddleware(async (c, next) => {
  const path = c.req.path.startsWith('/api/auth')
    ? c.req.path.slice('/api/auth'.length)
    : c.req.path;
  if (sensitiveAuthEndpoints[path] !== c.req.method) return next();

  return requireAccountOriginForBearer(c, next);
});


export const requireOpenKeyOriginForBearer = createMiddleware(async (c, next) => {
  const error = bearerFromOpenKeyOriginError(c.req.header('authorization'), c.req.header('origin'));
  if (error) return c.json({ error }, 403);
  await next();
});
