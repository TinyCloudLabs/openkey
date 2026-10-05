import { createMiddleware } from 'hono/factory';
import { resolveOriginPolicy } from '../origin-policy';

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

export const requireOpenKeyOriginForBearer = createMiddleware(async (c, next) => {
  const error = bearerFromOpenKeyOriginError(c.req.header('authorization'), c.req.header('origin'));
  if (error) return c.json({ error }, 403);
  await next();
});
