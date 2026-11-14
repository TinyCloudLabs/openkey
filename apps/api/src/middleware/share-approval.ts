import { createMiddleware } from 'hono/factory';

/** Check before CORS, authentication or body parsing; publication does not enable this flow. */
export const requireShareApproval = createMiddleware(async (c, next) => {
  if (process.env.OPENKEY_SHARE_APPROVAL !== 'true') return c.notFound();
  c.header('Cache-Control', 'no-store');
  await next();
});
