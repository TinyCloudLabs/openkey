import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { createLockedSubjectGuard } from '../services/locked-subject-guard';

function app(lockedUsers: Set<string>) {
  const database = {
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => ({ lockedAt: lockedUsers.has(where.id) ? new Date() : null }),
    },
  };
  const router = new Hono();
  const guard = createLockedSubjectGuard(database as never);
  router.use('/api/auth/oauth2/userinfo', guard);
  router.use('/api/auth/oauth2/introspect', guard);
  router.get('/api/auth/oauth2/userinfo', (c) => c.json({ sub: c.req.query('sub'), email: 'user@example.test' }));
  router.post('/api/auth/oauth2/introspect', (c) => c.json({ active: true, sub: c.req.query('sub') }));
  return router;
}

describe('locked subject guard (R9)', () => {
  test('userinfo for a locked user is an inactive token; others pass through', async () => {
    const router = app(new Set(['locked']));
    const refused = await router.request('/api/auth/oauth2/userinfo?sub=locked');
    expect(refused.status).toBe(401);
    expect(refused.headers.get('www-authenticate')).toContain('invalid_token');
    expect(await refused.json()).toEqual({ error: 'invalid_token', error_description: 'The access token is not active' });
    const allowed = await router.request('/api/auth/oauth2/userinfo?sub=open');
    expect(allowed.status).toBe(200);
    expect(await allowed.json()).toEqual({ sub: 'open', email: 'user@example.test' });
  });

  test('introspection of a locked user\'s token answers inactive', async () => {
    const router = app(new Set(['locked']));
    const locked = await router.request('/api/auth/oauth2/introspect?sub=locked', { method: 'POST' });
    expect(locked.status).toBe(200);
    expect(await locked.json()).toEqual({ active: false });
    const open = await router.request('/api/auth/oauth2/introspect?sub=open', { method: 'POST' });
    expect(await open.json()).toEqual({ active: true, sub: 'open' });
  });
});
