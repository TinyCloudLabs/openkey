import './tee-dev-env';
import { afterAll, beforeEach, describe, expect, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { Hono } from 'hono';
import { mockModules, replaceModules } from './mock-module';
import type * as OrgKeysRoutes from '../routes/org-keys';
import { addSession, asPrisma, fakeTee, ISSUER_DID, ORIGIN, RP_ID, SLUG, setupOrgKey } from './org-keys-fixtures';
import { signedTextFor, statementFor } from './org-issuer-statement-fixtures';
import { ISSUER_STATEMENT_KIND } from '../services/org-issuer-statement';

const user = { id: 'user_1', email: 'test@example.com' };
const MESSAGE = 'Sign in to the org console, nonce 42';
const otherOrigin = 'https://evil.example';
const ORG_BODY_ORG_ID = `o${'a'.repeat(26)}`;
const ORG_BODY = { orgId: ORG_BODY_ORG_ID, orgName: 'Beta', slug: SLUG };

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
const originalStatementFlag = process.env.ORG_ISSUER_STATEMENT_ENABLED;
afterAll(() => {
  if (originalFlag === undefined) delete process.env.ORG_KEY_CUSTODY_ENABLED;
  else process.env.ORG_KEY_CUSTODY_ENABLED = originalFlag;
  if (originalStatementFlag === undefined) delete process.env.ORG_ISSUER_STATEMENT_ENABLED;
  else process.env.ORG_ISSUER_STATEMENT_ENABLED = originalStatementFlag;
});

// Loaded after mockModules so the route captures the mocked db and tee. A file-specific
// query string gives this file its own module instance (see mock-module.ts).
const { createOrgKeysRouter } = (await import('../routes/org-keys?org-keys-route-test' as string)) as typeof OrgKeysRoutes;

type Ctx = Awaited<ReturnType<typeof setupOrgKey>>;

async function appFor(ctx: Ctx) {
  const router = createOrgKeysRouter({
    prisma: asPrisma(ctx.db),
    tee: ctx.tee,
    webauthn: () => ({ rpID: RP_ID, origin: ORIGIN }),
  });
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

// Counts ORG keys only: setupOrgKey also seeds the grantee's canonical PERSONAL key.
function orgKeyCount(ctx: Ctx): number {
  return ctx.state.keys.filter((key) => key.custody === 'ORG').length;
}

const postJson = (app: Hono, path: string, body: unknown) =>
  app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

// The origin is the browser-reported `requestingOrigin` in the JSON body. An
// undefined value is omitted from the JSON, which is the "missing" case.
const signChallenge = (app: Hono, keyId: string, requestingOrigin: string | undefined, message = MESSAGE) =>
  postJson(app, `/api/org-keys/${keyId}/sign-challenge`, { message, requestingOrigin });

const sign = (app: Hono, keyId: string, requestingOrigin: string | undefined) =>
  postJson(app, `/api/org-keys/${keyId}/sign`, {
    nonce: 'nonce_1',
    message: MESSAGE,
    assertion: {},
    requestingOrigin,
  });

// Every origin the allowlist must refuse: missing, opaque, other site, and the
// scheme, port, and trailing-slash near-misses of the real origin.
const refusedOrigins: [string, string | undefined][] = [
  ['missing requestingOrigin', undefined],
  ['opaque null origin', 'null'],
  ['other site', otherOrigin],
  ['scheme swap', ORIGIN.replace(/^https:/, 'http:')],
  ['port suffix', `${ORIGIN}:8443`],
  ['trailing slash', `${ORIGIN}/`],
];

beforeEach(() => {
  process.env.ORG_KEY_CUSTODY_ENABLED = 'true';
  // Default-off: statement signing stays disabled unless a test enables it.
  process.env.ORG_ISSUER_STATEMENT_ENABLED = 'false';
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
    expect((await postJson(app, '/api/org-keys', { orgId: 'o', orgName: 'O' })).status).toBe(404);
    expect(orgKeyCount(ctx)).toBe(1);
  });

  test('POST creates an ORG key and an OWNER grant for the caller after a fresh passkey', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await postJson(app, '/api/org-keys', ORG_BODY);
    expect(response.status).toBe(201);
    const body = (await response.json()) as { key: { keyId: string; address: string; controllerDid: string } };
    const created = ctx.state.keys.find((key) => key.id === body.key.keyId);
    expect(created).toMatchObject({ custody: 'ORG' });
    expect(ctx.state.orgKeys.find((row) => row.keyId === body.key.keyId)).toMatchObject({
      slug: SLUG,
      issuerDid: `did:web:${ORG_BODY_ORG_ID}.orgs.credentials.org`,
    });
    expect(
      ctx.state.grants.some(
        (grant) => grant.keyId === body.key.keyId && grant.role === 'OWNER' && grant.granteeUserId === 'user_1',
      ),
    ).toBe(true);
    expect(body.key.controllerDid).toBe(`did:pkh:eip155:1:${body.key.address}`);
  });

  test('POST refuses a supplied controllerDid and creates no key', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await postJson(app, '/api/org-keys', {
      ...ORG_BODY,
      controllerDid: 'did:pkh:eip155:1:0x0000000000000000000000000000000000000001',
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'controller_did_not_accepted' });
    expect(orgKeyCount(ctx)).toBe(1);
  });

  test('POST rejects a body missing required fields', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await postJson(app, '/api/org-keys', { orgId: 'org_2' });
    expect(response.status).toBe(400);
    expect(orgKeyCount(ctx)).toBe(1);
  });

  test('POST without slug is refused as org_record_incomplete and creates no key', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await postJson(app, '/api/org-keys', { orgId: ORG_BODY_ORG_ID, orgName: 'Beta' });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'org_record_incomplete' });
    expect(orgKeyCount(ctx)).toBe(1);
  });

  test('POST refuses a supplied issuerDid and creates no key', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await postJson(app, '/api/org-keys', { ...ORG_BODY, issuerDid: ISSUER_DID });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'invalid_field' });
    expect(orgKeyCount(ctx)).toBe(1);
  });

  test('POST refuses an orgId that is not a canonical OrgId and creates no key', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await postJson(app, '/api/org-keys', { ...ORG_BODY, orgId: 'org_2' });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'invalid_field' });
    expect(orgKeyCount(ctx)).toBe(1);
  });

  test('POST refuses a reserved slug and creates no key', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await postJson(app, '/api/org-keys', { ...ORG_BODY, slug: 'admin' });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'invalid_field' });
    expect(orgKeyCount(ctx)).toBe(1);
  });

  test('F7: POST without a passkey verified in the last 5 minutes is refused and creates no key', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);
    ctx.state.sessions[0] = { ...ctx.state.sessions[0], lastPasskeyAt: new Date(Date.now() - 10 * 60 * 1000) };

    const response = await postJson(app, '/api/org-keys', ORG_BODY);
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'passkey_step_up_required' });
    expect(orgKeyCount(ctx)).toBe(1);
  });

  test('F7: POST is refused when the session has never recorded a passkey verification', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);
    ctx.state.sessions.length = 0;
    addSession(ctx.state, 'user_1', null);

    const response = await postJson(app, '/api/org-keys', ORG_BODY);
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'passkey_step_up_required' });
    expect(orgKeyCount(ctx)).toBe(1);
  });

  for (const [label, origin] of refusedOrigins) {
    test(`sign-challenge refuses ${label} before classification and issues no challenge`, async () => {
      const ctx = await setupOrgKey();
      const app = await appFor(ctx);

      const response = await signChallenge(app, ctx.key.keyId, origin);
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ code: 'origin_not_allowed' });
      expect(ctx.state.challenges).toHaveLength(0);
    });

    test(`sign refuses ${label} before classification and records no audit`, async () => {
      const ctx = await setupOrgKey();
      const app = await appFor(ctx);

      const response = await sign(app, ctx.key.keyId, origin);
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ code: 'origin_not_allowed' });
      expect(ctx.state.audits).toHaveLength(0);
      expect(ctx.state.passkeys[0]?.counter).toBe(0);
    });
  }

  test('an Origin header does not stand in for the body requestingOrigin', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await app.request(`/api/org-keys/${ctx.key.keyId}/sign-challenge`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: ORIGIN },
      body: JSON.stringify({ message: MESSAGE }),
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'origin_not_allowed' });
    expect(ctx.state.challenges).toHaveLength(0);
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

  test('sign-challenge on a personal key is refused as no active org grant and issues no challenge', async () => {
    const ctx = await setupOrgKey();
    addPersonalKeyWithGrant(ctx.state);
    const app = await appFor(ctx);

    const response = await signChallenge(app, 'personal_1', ORIGIN);
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'no_active_grant' });
    expect(ctx.state.challenges).toHaveLength(0);
  });

  test('a challenge issued while statement signing was on cannot be signed after the flag is turned off', async () => {
    process.env.ORG_ISSUER_STATEMENT_ENABLED = 'true';
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);
    const message = statementFor(ctx.key);
    const issued = (await (await signChallenge(app, ctx.key.keyId, ORIGIN, message)).json()) as { nonce: string };
    process.env.ORG_ISSUER_STATEMENT_ENABLED = 'false';

    const response = await postJson(app, `/api/org-keys/${ctx.key.keyId}/sign`, {
      nonce: issued.nonce,
      message,
      assertion: { id: 'cred_1', response: { signature: 'AAAA' } },
      requestingOrigin: ORIGIN,
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'unsupported_message_kind' });
    expect(ctx.state.audits).toHaveLength(0);
    expect(ctx.state.passkeys[0]?.counter).toBe(0);
  });

  test('sign-challenge refuses every message while statement signing is off and issues no challenge', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await signChallenge(app, ctx.key.keyId, ORIGIN);
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'unsupported_message_kind' });
    expect(ctx.state.challenges).toHaveLength(0);
  });

  test('with statement signing enabled, sign-challenge returns the exact text the org key will sign', async () => {
    process.env.ORG_ISSUER_STATEMENT_ENABLED = 'true';
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);
    const message = statementFor(ctx.key);

    const response = await signChallenge(app, ctx.key.keyId, ORIGIN, message);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { kind: string; text: string; nonce: string };
    expect(body.kind).toBe(ISSUER_STATEMENT_KIND);
    expect(body.text).toBe(signedTextFor(message));
    expect(body.nonce).toEqual(expect.any(String));
    expect(ctx.state.challenges).toHaveLength(1);
    expect(ctx.state.challenges[0]).toMatchObject({ origin: ORIGIN });
  });

  test('sign-challenge requires a message', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await postJson(app, `/api/org-keys/${ctx.key.keyId}/sign-challenge`, { requestingOrigin: ORIGIN });
    expect(response.status).toBe(400);
  });

  test('sign requires a nonce, and the nonce is checked before grant or origin', async () => {
    const ctx = await setupOrgKey();
    const app = await appFor(ctx);

    const response = await postJson(app, `/api/org-keys/${ctx.key.keyId}/sign`, {
      message: MESSAGE,
      assertion: {},
      requestingOrigin: otherOrigin,
    });
    expect(response.status).toBe(400);
    expect(ctx.state.audits).toHaveLength(0);
  });
});
