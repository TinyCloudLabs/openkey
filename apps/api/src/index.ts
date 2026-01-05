// OpenKey API - Hono server with better-auth
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { auth } from './auth';
import { keysRouter } from './routes/keys';
import { accountRouter } from './routes/account';

// Create Hono app
const app = new Hono();

// Middleware
app.use('*', logger());
app.use('*', cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  credentials: true,
}));

// Health check
app.get('/health', (c) => c.json({ status: 'ok', tee: process.env.TEE_MODE || 'development' }));

// better-auth routes - mount at /api/auth
app.on(['POST', 'GET'], '/api/auth/**', async (c) => {
  const response = await auth.handler(c.req.raw);
  return response;
});

// Key management routes
app.route('/api/keys', keysRouter);

// Account management routes
app.route('/api/account', accountRouter);

// 404 handler
app.notFound((c) => c.json({ error: 'Not found' }, 404));

// Error handler
app.onError((err, c) => {
  console.error('API Error:', err);
  return c.json({ error: 'Internal server error' }, 500);
});

// Start server
const port = parseInt(process.env.API_PORT || '3001');

console.log(`OpenKey API starting on port ${port}...`);
console.log(`TEE Mode: ${process.env.TEE_MODE || 'development'}`);

export default {
  port,
  fetch: app.fetch,
};
