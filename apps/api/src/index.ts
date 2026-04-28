// OpenKey API - Hono server with better-auth
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { auth } from './auth';
import { keysRouter } from './routes/keys';
import { accountRouter } from './routes/account';
import { oauthAdminRouter } from './routes/oauth-admin';
import { passkeyProxyRouter } from './routes/passkey-proxy';
import { secretsRouter } from './routes/secrets';
import { variablesRouter } from './routes/variables';
import { delegateRouter } from './routes/delegate';
import { trackAuthorization, trackTokenExchange, trackUniqueUser } from './analytics';

// Create Hono app
const app = new Hono();

// Middleware
app.use('*', logger());

// Parse CORS_ORIGIN - supports comma-separated list or single origin
const corsOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map(o => o.trim());

// OAuth token endpoint: allow any origin (PKCE provides security for public clients)
app.use('/api/auth/oauth2/token', cors({
  origin: '*',
  credentials: false, // credentials not needed for token exchange
}));

// All other routes: restricted to whitelisted origins
app.use('*', cors({
  origin: corsOrigins.length === 1 ? corsOrigins[0]! : corsOrigins,
  credentials: true,
}));

// Health check
app.get('/health', (c) => c.json({ status: 'ok', tee: process.env.TEE_MODE || 'development' }));

// Analytics middleware - runs BEFORE auth handler, uses next() to capture response
// POST /api/auth/oauth2/token → track token exchange + unique user
app.use('/api/auth/oauth2/token', async (c, next) => {
  // Clone the request body before auth handler consumes it
  const clonedReq = c.req.raw.clone();

  await next();

  // Only track successful token exchanges
  if (c.res.status !== 200) return;

  try {
    const body = await clonedReq.formData().catch(() => null);
    const clientId = body?.get('client_id') as string | null;

    if (clientId) {
      // Fire-and-forget: don't block the response
      trackTokenExchange(clientId).catch((err) =>
        console.error('[Analytics] Failed to track token exchange:', err)
      );
      trackUniqueUser(clientId).catch((err) =>
        console.error('[Analytics] Failed to track unique user:', err)
      );
    }
  } catch (err) {
    console.error('[Analytics] Error in token tracking middleware:', err);
  }
});

// GET /api/auth/oauth2/authorize → track authorization on successful redirect
app.use('/api/auth/oauth2/authorize', async (c, next) => {
  await next();

  // Successful authorizations result in a 302 redirect with a code
  if (c.res.status !== 302) return;

  try {
    const url = new URL(c.req.url);
    const clientId = url.searchParams.get('client_id');

    if (clientId) {
      trackAuthorization(clientId).catch((err) =>
        console.error('[Analytics] Failed to track authorization:', err)
      );
    }
  } catch (err) {
    console.error('[Analytics] Error in authorization tracking middleware:', err);
  }
});

// better-auth routes - mount at /api/auth
// Avoid async/await wrapper to preserve AsyncLocalStorage context in Bun
app.on(['POST', 'GET'], '/api/auth/*', (c) => {
  return auth.handler(c.req.raw);
});

// Key management routes
app.route('/api/keys', keysRouter);

// Account management routes
app.route('/api/account', accountRouter);

// Passkey proxy routes (for iframe embed mode)
app.route('/api/passkey', passkeyProxyRouter);

// OAuth admin routes (protected by ADMIN_API_KEY)
app.route('/api/admin/oauth', oauthAdminRouter);

// Secrets and variables routes (TinyCloud-backed)
app.route('/api/secrets', secretsRouter);
app.route('/api/variables', variablesRouter);

// Delegate route (CLI auth flow)
app.route('/api/delegate', delegateRouter);

// 404 handler
app.notFound((c) => c.json({ error: 'Not found' }, 404));

// Error handler
app.onError((err, c) => {
  console.error('API Error:', err);
  return c.json({ error: 'Internal server error' }, 500);
});

// One-time startup migration: ensure all OAuth clients have full scopes
import { createPrismaClient } from '@openkey/db';
const ALL_SCOPES = ['openid', 'email', 'keys', 'offline_access'];

(async () => {
  try {
    const prisma = createPrismaClient();
    const result = await prisma.oauthClient.updateMany({
      where: {
        scopes: { equals: ['openid'] },
      },
      data: {
        scopes: ALL_SCOPES,
      },
    });
    if (result.count > 0) {
      console.log(`[Startup] Updated ${result.count} OAuth client(s) to full scopes`);
    }
    await prisma.$disconnect();
  } catch (err) {
    console.error('[Startup] Failed to update OAuth client scopes:', err);
  }
})();

// Start server
const port = parseInt(process.env.API_PORT || '3001');

console.log(`OpenKey API starting on port ${port}...`);
console.log(`TEE Mode: ${process.env.TEE_MODE || 'development'}`);

export default {
  port,
  fetch: app.fetch,
};
