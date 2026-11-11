import { afterAll, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';
import type { SessionContext } from '../middleware/session';
import { asPrisma, ORIGIN, setupOrgKey } from './org-keys-fixtures';
import type * as Routes from '../routes/org-keys';

const { createOrgKeysRouter } = await import('../routes/org-keys?admin-signing-test' as string) as typeof Routes;
const originalFlag = process.env.ORG_KEY_CUSTODY_ENABLED;
afterAll(() => {
  if (originalFlag === undefined) delete process.env.ORG_KEY_CUSTODY_ENABLED;
  else process.env.ORG_KEY_CUSTODY_ENABLED = originalFlag;
});

for (const endpoint of ['sign-challenge', 'sign']) {
  test(`${endpoint} refuses an accepted admin before classifying any message`, async () => {
    process.env.ORG_KEY_CUSTODY_ENABLED = 'true';
    const ctx = await setupOrgKey();
    ctx.state.grants[0]!.role = 'ADMIN';
    const sessionMiddleware = createMiddleware<SessionContext>(async (c, next) => {
      c.set('user', { id: 'user_1', email: 'test@example.com' });
      c.set('session', { id: 'session_1', userId: 'user_1', expiresAt: new Date(Date.now() + 60_000) });
      await next();
    });
    const app = new Hono().route('/api/org-keys', createOrgKeysRouter({
      prisma: asPrisma(ctx.db), tee: ctx.tee, sessionMiddleware,
    }));
    for (const message of ['unknown operation', 'Sign in to the org console, nonce 42']) {
      const response = await app.request(`/api/org-keys/${ctx.key.keyId}/${endpoint}`, {
        method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN },
        body: JSON.stringify({ message, nonce: 'unused', assertion: {} }),
      });
      expect(response.status).toBe(403);
      expect(await response.json()).toEqual({ error: 'Forbidden', code: 'admin_signing_disabled' });
    }
    expect(ctx.state.challenges).toHaveLength(0);
    expect(ctx.state.audits).toHaveLength(0);
  });
}
