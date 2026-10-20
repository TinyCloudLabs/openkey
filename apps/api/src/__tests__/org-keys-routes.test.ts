import { afterAll, beforeEach, describe, expect, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { Hono } from 'hono';
import { mockModules, replaceModules } from './mock-module';
import type * as OrgKeysRoutes from '../routes/org-keys';
import { fakeTee, ORIGIN, setupOrgKey, asPrisma } from './org-keys-fixtures';

const user = { id: 'user_1', email: 'test@example.com' };
const otherOrigin = 'https://evil.example';

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({}) }),
  '@openkey/tee': () => ({ createTeeClient: () => fakeTee() }),
});

const originalFlag = process.env.ORG_KEY_CUSTODY_ENABLED;
afterAll(() => {
  if (originalFlag === undefined) delete process.env.ORG_KEY_CUSTODY_ENABLED;
  else process.env.ORG_KEY_CUSTODY_ENABLED = originalFlag;
});

// Loaded after mockModules so the route captures the mocked db and tee. A file-specific
// query string gives this file its own module instance (see mock-module.ts).
const { createOrgKeysRouter } = (await import('../routes/org-keys?org-keys-route-test' as string)) as typeof OrgKeysRoutes;

async function appFor(ctx: Awaited<ReturnType<typeof setupOrgKey>>) {
  const router = createOrgKeysRouter({ prisma: asPrisma(ctx.db), tee: ctx.tee });
  return new Hono().route('/api/org-keys', router);
}

// A personal key owned by user_1 that also carries an active OWNER grant. The
// grant must not make it visible through the org-key routes.
function addPersonalKeyWithGrant(state: { keys: Record<string, unknown>[]; grants: Record<string, unknown>[] }) {
  state.keys.push({
    id: 'personal_1',
    userId: 'user_1',
    custody: 'PERSONAL',
    address: '0x0000000000000000000000000000000000000001',
    label: 'personal',
    sealedBlob: null,
    archivedAt: null,
    keyType: 'MANAGED',
  });
  state.grants.push({
    id: 'grant_personal',
    keyId: 'personal_1',
    granteeUserId: 'user_1',
    role: 'OWNER',
    revokedAt: null,
  });
}

const sign = (app: Hono, keyId: string, origin: string, body: unknown = { message: 'anything', assertion: {} }) =>
  app.request(`/api/org-keys/${keyId}/sign`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin },
    body: JSON.stringify(body),
  });

beforeEach(() => {
  process.env.ORG_KEY_CUSTODY_ENABLED = 'true';
});

describe('org key routes', () => {
  test('lists only ORG keys the caller holds an active grant on', async () => {
    const ctx = await setupOrgKey();
    addPersonalKeyWithGrant(ctx.state);
    const app = await appFor(ctx);

    const response = await app.request('/api/org-keys');
    expect(response.status).toBe(200);
    const body = (await response.json()) as { keys: { keyId: string; role: string }[] };
    expect(body.keys.map((key) => key.keyId)).toEqual([ctx.key.keyId]);
    expect(body.keys[0]?.role).toBe('OWNER');
  });

  test('a personal key is not reachable through the org-key get route', async () => {
    const ctx = await setupOrgKey();
    addPersonalKeyWithGrant(ctx.state);
    const app = await appFor(ctx);

    const response = await app.request('/api/org-keys/personal_1');
    expect(response.status).toBe(404);
  });

  test('a revoked grant removes the key from the list and from the get route', async () => {
    const ctx = await setupOrgKey();
    ctx.state.grants[0]!.revokedAt = new Date();
    const app = await appFor(ctx);

    const list = (await (await app.request('/api/org-keys')).json()) as { keys: unknown[] };
    expect(list.keys).toHaveLength(0);
    expect((await app.request(`/api/org-keys/${ctx.key.keyId}`)).status).toBe(404);
  });

  test('is a 404 for every route when the custody flag is off', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);
    process.env.ORG_KEY_CUSTODY_ENABLED = 'false';

    expect((await app.request('/api/org-keys')).status).toBe(404);
    expect((await app.request(`/api/org-keys/${ctx.key.keyId}`)).status).toBe(404);
    expect(
      (
        await app.request('/api/org-keys', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ orgId: 'o', orgName: 'O', controllerDid: 'did:example:o' }),
        })
      ).status,
    ).toBe(404);
    expect(ctx.state.keys).toHaveLength(1);
  });

  test('POST creates an ORG key and an OWNER grant for the caller', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await app.request('/api/org-keys', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ orgId: 'org_2', orgName: 'Beta', controllerDid: 'did:example:beta' }),
    });
    expect(response.status).toBe(201);
    const body = (await response.json()) as { key: { keyId: string } };
    const created = ctx.state.keys.find((key) => key.id === body.key.keyId);
    expect(created).toMatchObject({ custody: 'ORG' });
    expect(ctx.state.grants.some((grant) => grant.keyId === body.key.keyId && grant.role === 'OWNER' && grant.granteeUserId === 'user_1')).toBe(true);
  });

  test('POST rejects a body missing required fields', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await app.request('/api/org-keys', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ orgId: 'org_2' }),
    });
    expect(response.status).toBe(400);
    expect(ctx.state.keys).toHaveLength(1);
  });

  test('sign on a personal key is refused as no active org grant', async () => {
    const ctx = await setupOrgKey();
    addPersonalKeyWithGrant(ctx.state);
    const app = await appFor(ctx);

    const response = await sign(app, 'personal_1', ORIGIN);
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'no_active_grant' });
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('sign from an origin outside the allowlist is refused before any signing', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await sign(app, ctx.key.keyId, otherOrigin);
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'origin_not_allowed' });
    expect(ctx.state.audits).toHaveLength(0);
  });

  test('sign refuses every message in K2a (fail closed) and records no audit', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await sign(app, ctx.key.keyId, ORIGIN, {
      message: 'Sign in to the org console, nonce 42',
      assertion: {},
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'unsupported_message_kind' });
    expect(ctx.state.audits).toHaveLength(0);
    expect(ctx.state.passkeys[0]?.counter).toBe(0);
  });

  test('sign-challenge refuses every message in K2a (fail closed)', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await app.request(`/api/org-keys/${ctx.key.keyId}/sign-challenge`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'Sign in to the org console, nonce 42' }),
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'unsupported_message_kind' });
  });
});
