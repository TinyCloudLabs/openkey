import { createMiddleware } from 'hono/factory';

export function signInContinuationEnabled(): boolean {
  return process.env.OPENKEY_SIGNIN_CONTINUATION === 'true';
}

/** Run before session/body handling so the dark path has no side effects. */
export const requireSignInContinuation = createMiddleware(async (c, next) => {
  if (!signInContinuationEnabled()) return c.notFound();
  await next();
});
