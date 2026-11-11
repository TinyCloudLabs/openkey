import { afterAll, expect, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { createOrgKeyAdminsRouter } from '../routes/org-key-admins';
import { OrgKeyRefusal } from '../services/org-keys';
import { asPrisma, ORIGIN, RP_ID } from './org-keys-fixtures';
import type { SessionContext } from '../middleware/session';

const flag = process.env.ORG_KEY_CUSTODY_ENABLED;
afterAll(() => {
  if (flag === undefined) delete process.env.ORG_KEY_CUSTODY_ENABLED;
  else process.env.ORG_KEY_CUSTODY_ENABLED = flag;
});
test('an invitation send refusal carries 429 and Retry-After through the public route', async () => {
  process.env.ORG_KEY_CUSTODY_ENABLED = 'true';
  const app = createOrgKeyAdminsRouter({
    prisma: asPrisma({ $transaction: async () => { throw new OrgKeyRefusal(429, 'invitation_rate_limited', 'Forbidden', 37); } }),
    sessionMiddleware: createMiddleware<SessionContext>(async (c, next) => {
      c.set('user', { id: 'owner', email: 'owner@example.test' });
      c.set('session', { id: 'owner-session', userId: 'owner', expiresAt: new Date(Date.now() + 60000) });
      await next();
    }),
    webauthn: () => ({ origin: ORIGIN, rpID: RP_ID }),
  });
  const response = await app.request('/org-key/admin-invitations', {
    method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'person@example.test', nonce: 'nonce', assertion: {} }),
  });
  expect(response.status).toBe(429);
  expect(response.headers.get('retry-after')).toBe('37');
  expect(await response.json()).toEqual({ error: 'Forbidden', code: 'invitation_rate_limited' });
});
