// TC-3232: the required Terms acceptance, through the whole API (routes, Better Auth's OAuth provider, the
// tracked migrations on PGlite). The server is the gate: every session route, the provider's authorize,
// consent, continue, token and userinfo, and the native and device approvals refuse an account until it
// accepts the current version. Runs in a child process, as the other full-API tests do.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';
import type * as ReviewerAccounts from '../services/reviewer-accounts';
import type * as Terms from '../services/terms';
import { mockModules } from './mock-module';
import { NATIVE_DELEGATION_ENDPOINT_PATHS, OPENKEY_SESSION_PROOF_HEADER } from '../services/native-delegation/public-protocol';
import { credentialHash } from '../services/native-delegation/session-proof';
import { stepUpCodeDigest } from '../services/email-code-storage';

const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_TERMS_TEST_CHILD !== '1') {
  test('the Terms gate across the API', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_TERMS_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'terms-acceptance-isolated-test-secret',
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: 'https://openkey.test',
        CORS_ORIGIN: 'https://openkey.test',
        OAUTH_DYNAMIC_CLIENT_REGISTRATION: 'true',
        RESEND_API_KEY: '',
        GOOGLE_CLIENT_ID: '',
        GOOGLE_CLIENT_SECRET: '',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    expect(exitCode, stdout + stderr).toBe(0);
  }, 300_000);
} else {
  const api = 'https://api.openkey.test';
  const issuer = `${api}/api/auth`;
  const web = 'https://openkey.test';
  const callback = 'https://app.example.test/callback';
  const verifier = 'terms-acceptance-pkce-verifier-0123456789012345678901';
  const VERSION = '2026-12-01';
  const SHA = 'a'.repeat(64);
  const TERMS_URL = `${web}/auth/terms`;
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let secret: string;
  let cookieName: string;
  let counter = 0;
  let initializeReviewers: typeof ReviewerAccounts.initializeReviewers;
  let seedReviewerTerms: typeof ReviewerAccounts.seedReviewerTerms;
  let hasAcceptedTerms: typeof Terms.hasAcceptedTerms;
  let termsRelease: typeof Terms.termsRelease;

  // The checked-in terms-release.json, replaced by one object the tests rewrite: the API reads it per call.
  const releaseFile: Record<string, unknown> = {};
  function release(version: string | null, extra: Record<string, unknown> = {}) {
    Object.assign(releaseFile, {
      version, requiredVersion: null, textSha256: version ? SHA : null, whatChanged: null, privacyChanged: false, ...extra,
    });
  }
  release(null);
  await mockModules({ '../terms-release.json': () => ({ default: releaseFile }) });

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-terms-'));
    const database = new PGlite(directory);
    try {
      const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) {
        await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
    } finally {
      await database.close();
    }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    release(null);
    // Loaded after DATABASE_URL is set and the release file is replaced: the API modules open their
    // database, and bind the release file, when loaded.
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    ({ initializeReviewers, seedReviewerTerms } = await import('../services/reviewer-accounts'));
    ({ hasAcceptedTerms, termsRelease } = await import('../services/terms'));
    const context = await authModule.auth.$context;
    secret = context.secret;
    cookieName = context.authCookies.sessionToken.name;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  const request = (url: string, init: RequestInit = {}, cookie?: string) => app.fetch(new Request(url, {
    ...init, headers: { ...(cookie ? { cookie, origin: web } : {}), ...init.headers },
  }));
  const json = (url: string, body: unknown, cookie?: string) => request(url, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  }, cookie);
  const form = (path: string, values: Record<string, string>) => request(`${issuer}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(values),
  });
  const accept = (cookie: string, body: unknown = { version: VERSION }) => json(`${api}/api/account/terms/accept`, body, cookie);
  const status = async (cookie: string) => (await request(`${api}/api/account/terms`, {}, cookie)).json() as Promise<Record<string, unknown>>;
  const rows = (userId: string) => prisma.termsAcceptance.findMany({ where: { userId } });

  async function signedIn() {
    const n = ++counter;
    const userId = `terms-user-${n}-${randomUUID()}`;
    const token = randomUUID();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    await prisma.ethereumKey.create({ data: { userId, address: `0x${n.toString(16).padStart(40, '0')}`, publicKey: '0x1', keyType: 'EXTERNAL' } });
    await prisma.session.create({ data: { id: `terms-session-${n}`, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    // A bearer is the signed session token, as `set-auth-token` hands it out.
    return { userId, token, cookie, bearer: cookie.slice(cookie.indexOf('=') + 1) };
  }

  async function expectTermsRequired(response: Response) {
    expect(response.status, await response.clone().text()).toBe(403);
    expect(await response.json()).toMatchObject({ error: 'terms_required', terms_url: TERMS_URL });
  }

  describe('the acceptance record', () => {
    test('GET reports the release; only the current version is accepted and recorded', async () => {
      release(VERSION, { whatChanged: '  Plain line on what changed.  ' });
      const { cookie, userId } = await signedIn();
      expect(await status(cookie)).toEqual({
        version: VERSION, effective: VERSION, whatChanged: 'Plain line on what changed.', privacyChanged: false,
        requiresAcceptance: true, previouslyAccepted: false,
      });
      for (const body of [{ version: '2026-11-01' }, { version: '2027-01-01' }, {}, null, { version: [VERSION] }]) {
        const refused = await accept(cookie, body);
        expect(refused.status).toBe(409);
        expect(await refused.json()).toEqual({ error: 'terms_version_mismatch', version: VERSION });
      }
      expect(await rows(userId)).toEqual([]);

      expect((await accept(cookie)).status).toBe(200);
      const [row] = await rows(userId);
      expect(row).toMatchObject({ userId, documentId: 'terms', version: VERSION, textSha256: SHA, surface: 'web' });
      expect(row!.appVersion).toMatch(/\+/);
      expect(await status(cookie)).toMatchObject({ requiresAcceptance: false, previouslyAccepted: true });
    });

    test('with no release configured nothing is required and nothing can be accepted', async () => {
      release(null);
      const { cookie, userId } = await signedIn();
      expect(await status(cookie)).toMatchObject({ version: null, requiresAcceptance: false });
      expect((await accept(cookie)).status).toBe(409);
      expect(await rows(userId)).toEqual([]);
    });

    test('two tabs accepting at once leave one row, and a later accept keeps the first', async () => {
      release(VERSION);
      const { cookie, userId } = await signedIn();
      const responses = await Promise.all(Array.from({ length: 5 }, () => accept(cookie)));
      expect(responses.map((response) => response.status)).toEqual([200, 200, 200, 200, 200]);
      const [first, ...others] = await rows(userId);
      expect(others).toEqual([]);
      expect((await accept(cookie)).status).toBe(200);
      expect(await rows(userId)).toEqual([first!]);
    });

    test('an acceptance cannot be rewritten', async () => {
      release(VERSION);
      const { cookie, userId } = await signedIn();
      await accept(cookie);
      const [row] = await rows(userId);
      const update = prisma.termsAcceptance.update({ where: { id: row!.id }, data: { version: '2027-01-01' } });
      expect(await update.then(() => 'updated', () => 'refused')).toBe('refused');
      expect(await rows(userId)).toEqual([row!]);
    });

    test('a native sheet records its client; an unknown client or surface is refused', async () => {
      release(VERSION);
      const { cookie, userId } = await signedIn();
      expect((await accept(cookie, { version: VERSION, surface: 'native', clientId: 'no-such-client' })).status).toBe(400);
      expect((await accept(cookie, { version: VERSION, surface: 'cli' })).status).toBe(400);
      expect(await rows(userId)).toEqual([]);
      const { clientId } = await register();
      expect((await accept(cookie, { version: VERSION, surface: 'native', clientId })).status).toBe(200);
      expect((await rows(userId))[0]).toMatchObject({ surface: `native:${clientId}` });
    });

    test('an editorial update keeps earlier acceptances; a required one asks again', async () => {
      release(VERSION);
      const { cookie } = await signedIn();
      await accept(cookie);
      release('2026-12-15', { requiredVersion: VERSION });
      expect(await status(cookie)).toMatchObject({ version: '2026-12-15', requiresAcceptance: false });
      expect((await request(`${api}/api/keys`, {}, cookie)).status).toBe(200);

      release('2026-12-15');
      expect(await status(cookie)).toMatchObject({ requiresAcceptance: true, previouslyAccepted: true });
      await expectTermsRequired(await request(`${api}/api/keys`, {}, cookie));
      expect((await accept(cookie, { version: '2026-12-15' })).status).toBe(200);
      expect((await request(`${api}/api/keys`, {}, cookie)).status).toBe(200);
    });
  });

  describe('the release file', () => {
    const valid = { version: VERSION, requiredVersion: null, textSha256: SHA, whatChanged: null, privacyChanged: false };

    test('the checked-in file is a valid release: a date version and a 64-hex text hash', async () => {
      const shipped = JSON.parse(await readFile(join(root, 'apps/api/src/terms-release.json'), 'utf8'));
      // test-ruling TC-3766 openkey #684 apps/api/src/__tests__/terms-acceptance.integration.test.ts:222 (2026-11-22): yes, exactly as you wrote it. When the checked-in version is null, expect termsRelease(shipped) to be null and return; otherwise the date and hash assertions run unchanged. Nothing else changes.
      if (shipped.version === null) {
        expect(termsRelease(shipped)).toBeNull();
        return;
      }
      const parsed = termsRelease(shipped);
      expect(parsed).not.toBeNull();
      expect(parsed!.version).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(parsed!.textSha256).toMatch(/^[0-9a-f]{64}$/);
    });

    test('a release defaults its required version to itself; an editorial one may require less', () => {
      expect(termsRelease(valid)).toEqual({ version: VERSION, requiredVersion: VERSION, textSha256: SHA, whatChanged: null, privacyChanged: false });
      expect(termsRelease({ ...valid, version: '2026-12-15', requiredVersion: VERSION })?.requiredVersion).toBe(VERSION);
    });

    test.each([
      ['an impossible date', { ...valid, version: '2026-02-30' }],
      ['a version that is not a date', { ...valid, version: 'v2' }],
      ['a required version after the version', { ...valid, requiredVersion: '2027-01-01' }],
      ['no text hash', { ...valid, textSha256: null }],
      ['an uppercase or short hash', { ...valid, textSha256: 'A'.repeat(64) }],
      ['privacyChanged as a string', { ...valid, privacyChanged: 'true' }],
      ['whatChanged as a number', { ...valid, whatChanged: 1 }],
      ['an unknown field', { ...valid, effective: VERSION }],
      ['a missing field', { version: VERSION, textSha256: SHA, whatChanged: null, privacyChanged: false }],
      ['release details with no version', { ...valid, version: null }],
      ['an array', [valid]],
    ])('%s refuses the file (the API will not start)', (_name, file) => {
      expect(() => termsRelease(file)).toThrow('Invalid terms-release.json');
    });
  });

  describe('session routes', () => {
    const gated: Array<[string, string, string, unknown]> = [
      ['account', 'GET', '/api/account/auto-sign', undefined],
      ['keys', 'GET', '/api/keys', undefined],
      ['delegate', 'POST', '/api/delegate/prepare', {}],
      ['device approve', 'POST', '/api/device-authorizations/no-such-transaction/approve', {}],
      ['native prepare', 'POST', '/api/oauth/tinycloud/requests/no-such-request/prepare', {}],
      ['native approve', 'POST', '/api/oauth/tinycloud/requests/no-such-request/approve', {}],
    ];
    const send = (cookie: string, method: string, path: string, body?: unknown) => request(`${api}${path}`, {
      method, ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
    }, cookie);

    test.each(gated)('%s refuses with terms_required until the account accepts, then answers', async (_name, method, path, body) => {
      release(VERSION);
      const { cookie } = await signedIn();
      await expectTermsRequired(await send(cookie, method, path, body));
      expect((await accept(cookie)).status).toBe(200);
      const after = await send(cookie, method, path, body);
      expect(after.status).not.toBe(401);
      expect(await after.text()).not.toContain('terms_required');
    });

    test('a bearer session token (CLI, widget) gets the same refusal with the URL to open', async () => {
      release(VERSION);
      const { bearer } = await signedIn();
      const response = await request(`${api}/api/keys`, { headers: { authorization: `Bearer ${bearer}`, origin: web } });
      expect(response.status).toBe(403);
      expect(await response.json()).toEqual({
        error: 'terms_required', error_description: `Open ${TERMS_URL} to accept the Terms of Service.`, terms_url: TERMS_URL,
      });
    });

    test('with no release configured the routes answer as before', async () => {
      release(null);
      const { cookie } = await signedIn();
      expect((await request(`${api}/api/keys`, {}, cookie)).status).toBe(200);
    });

    test('denying a native request stays open before acceptance', async () => {
      release(VERSION);
      const { cookie } = await signedIn();
      const response = await send(cookie, 'POST', '/api/oauth/tinycloud/requests/no-such-request/deny', {});
      expect(await response.text()).not.toContain('terms_required');
    });
  });

  // Leaving never requires agreeing: an account that hasn't accepted the current Terms can still delete itself,
  // disconnect apps, stop renewals, revoke what it delegated, and deny what it is asked to approve.
  describe('ways out', () => {
    const send = (cookie: string, method: string, path: string, body?: unknown) => request(`${api}${path}`, {
      method, ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
    }, cookie);
    /** An account that accepted an earlier release, now asked to accept a new required one. */
    async function behindNewTerms() {
      release(VERSION);
      const account = await signedIn();
      expect((await accept(account.cookie)).status).toBe(200);
      release('2026-12-15');
      await expectTermsRequired(await send(account.cookie, 'GET', '/api/keys'));
      return account;
    }

    test('the account can be deleted, with its email step-up', async () => {
      const { cookie, userId, token } = await behindNewTerms();
      const { id: sessionId } = await prisma.session.findFirstOrThrow({ where: { token } });
      const { email } = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
      const { stepUpIdentifier } = await import('../services/email-otp-step-up');

      // No mail service in this test: the send answers past the gate, and the code is the one it would store.
      const sent = await send(cookie, 'POST', '/api/account/step-up/email-otp/send', { purpose: 'delete_account' });
      expect(await sent.text()).not.toContain('terms_required');
      await prisma.verification.deleteMany({ where: { identifier: stepUpIdentifier(sessionId, email, 'delete_account') } });
      await prisma.verification.create({ data: {
        id: randomUUID(), identifier: stepUpIdentifier(sessionId, email, 'delete_account'),
        value: `${stepUpCodeDigest(stepUpIdentifier(sessionId, email, 'delete_account'), '123456')}:0`,
        expiresAt: new Date(Date.now() + 300_000),
      } });
      const verified = await send(cookie, 'POST', '/api/account/step-up/email-otp/verify', { purpose: 'delete_account', code: '123456' });
      expect(verified.status, await verified.clone().text()).toBe(200);

      const deleted = await send(cookie, 'POST', '/api/account/delete', { confirmation: 'DELETE MY ACCOUNT' });
      expect(deleted.status, await deleted.clone().text()).toBe(200);
      expect(await prisma.user.findUnique({ where: { id: userId } })).toBeNull();
    });

    test('the passkey step-up answers past the gate', async () => {
      const { cookie } = await behindNewTerms();
      for (const path of ['/api/account/step-up/passkey/options', '/api/account/step-up/passkey/verify']) {
        const response = await send(cookie, 'POST', path, {});
        expect(response.status).not.toBe(401);
        expect(await response.text()).not.toContain('terms_required');
      }
    });

    type Consent = { id: string; clientId: string };
    test.each([
      ['a TinyCloud app', 'tinycloud:delegation', (consent: Consent) => `/api/account/tinycloud-apps/${consent.clientId}`],
      ['an MCP app', 'tinycloud:mcp', (consent: Consent) => `/api/account/tinycloud-apps/mcp/${consent.id}`],
      ['an identity app', 'tinycloud:identity', (consent: Consent) => `/api/account/tinycloud-apps/identity/${consent.id}`],
    ])('%s can be disconnected', async (_name, scope, path) => {
      const { cookie, userId } = await behindNewTerms();
      const { clientId } = await register();
      const consent = await prisma.oauthConsent.create({ data: { id: randomUUID(), userId, clientId, scopes: ['openid', scope] } });
      const response = await send(cookie, 'DELETE', path(consent), { confirmation: 'DISCONNECT' });
      expect(response.status, await response.clone().text()).toBe(200);
      expect(await prisma.oauthConsent.findUnique({ where: { id: consent.id } })).toBeNull();
    });

    test.each([
      ['the account', '/api/account', (body: Record<string, unknown>) => expect(body.user).toHaveProperty('email')],
      ['its connected apps', '/api/account/tinycloud-apps', (body: Record<string, unknown>) => expect(body).toMatchObject({ apps: [], mcpApps: [], identityApps: [] })],
      ['its renewing permissions', '/api/account/renewal-leases', (body: Record<string, unknown>) => expect(body).toHaveProperty('leases')],
    ])('%s can be read, so the page offering the ways out can show them', async (_name, path, check) => {
      const { cookie } = await behindNewTerms();
      const response = await send(cookie, 'GET', path);
      expect(response.status, await response.clone().text()).toBe(200);
      check(await response.json() as Record<string, unknown>);
    });

    test('an OAuth consent can be denied; agreeing to it still cannot', async () => {
      release(VERSION);
      const { cookie } = await signedIn();
      const { clientId, scope } = await register();
      const oauthQuery = (await authorize(cookie, clientId, scope)).searchParams.toString();
      const denied = await json(`${issuer}/oauth2/consent`, { accept: false, oauth_query: oauthQuery }, cookie);
      expect(denied.status, await denied.clone().text()).toBe(200);
      const back = new URL((await denied.json() as { url: string }).url);
      expect(`${back.origin}${back.pathname}`).toBe(callback);
      expect(back.searchParams.get('error')).toBe('access_denied');
      expect(back.searchParams.get('code')).toBeNull();
      await expectTermsRequired(await json(`${issuer}/oauth2/consent`, { accept: true, oauth_query: oauthQuery }, cookie));
      await expectTermsRequired(await json(`${issuer}/oauth2/continue`, { accept: false, postLogin: true, oauth_query: oauthQuery }, cookie));
    });

    test('a consent body too large to read stays gated, denial or not', async () => {
      release(VERSION);
      const { cookie } = await signedIn();
      const { clientId, scope } = await register();
      const oauthQuery = (await authorize(cookie, clientId, scope)).searchParams.toString();
      await expectTermsRequired(await json(`${issuer}/oauth2/consent`, { accept: false, oauth_query: oauthQuery, padding: 'x'.repeat(64 * 1024) }, cookie));
    });

    // Only deleting the account is a way out; the other step-up purposes manage the account.
    test.each([
      ['send', { purpose: 'link' }],
      ['send', {}],
      ['send', { purpose: 'passkey_register' }],
      ['send', { purpose: 'passkey_remove' }],
      ['verify', { purpose: 'link', code: '123456' }],
      ['verify', { code: '123456' }],
    ])('an email step-up to %s for anything but deleting the account stays gated (%j)', async (step, body) => {
      const { cookie } = await behindNewTerms();
      await expectTermsRequired(await send(cookie, 'POST', `/api/account/step-up/email-otp/${step}`, body));
    });

    test('an owner-revocation handoff can be claimed; a sign-in handoff cannot', async () => {
      const { cookie } = await behindNewTerms();
      const secret = () => randomBytes(32).toString('base64url');
      const delivery = () => ({ handoffId: secret(), state: secret(), cancelSecret: secret() });
      const revocation = {
        transportVersion: 2,
        request: {
          kind: 'owner-revocation',
          ownerDid: 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111',
          cid: 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe',
          nonce: randomUUID().replaceAll('-', ''),
          expiresAt: new Date(Date.now() + 9 * 60_000).toISOString(),
        },
        delivery: delivery(),
      };
      const claimed = await send(cookie, 'POST', '/api/delegate/handoffs/claim', revocation);
      expect(claimed.status, await claimed.clone().text()).toBe(201);

      const signIn = { transportVersion: 2, request: { protocolVersion: 1, siwe: 'x', jwk: {}, host: 'https://node.example', sessionDid: 'did:key:z' }, delivery: delivery() };
      await expectTermsRequired(await send(cookie, 'POST', '/api/delegate/handoffs/claim', signIn));
    });

    test.each([
      ['stopping a renewal lease', 'POST', '/api/account/renewal-leases/no-such-lease/stop', {}],
      ['revoking a Nostr signing grant', 'DELETE', '/api/keys/nostr/grants/no-such-grant', undefined],
      ['preparing an owner revocation', 'POST', '/api/delegate/owner-revocation/prepare', {}],
      ['signing an owner revocation', 'POST', '/api/delegate/owner-revocation/sign', {}],
      ['cancelling a claimed handoff', 'POST', '/api/delegate/handoffs/cancel-claimed', {}],
      ['denying an approval request', 'POST', '/api/approval-requests/no-such-request/deny', {}],
      ['denying a device sign-in', 'POST', '/api/device-authorizations/no-such-transaction/deny', {}],
    ])('%s answers past the gate', async (_name, method, path, body) => {
      const { cookie } = await behindNewTerms();
      const response = await send(cookie, method, path, body);
      expect(response.status).not.toBe(401);
      expect(await response.text()).not.toContain('terms_required');
    });
  });

  // What an account already handed out stops working for it, and nothing extends it, until it accepts.
  describe('access granted before the gate', () => {
    const sign = (headers: Record<string, string>) => request(`${api}/api/delegate/sign`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: '{}',
    });

    test('an app\'s OAuth token no longer signs, until the account accepts', async () => {
      release(VERSION);
      const { cookie, userId } = await signedIn();
      const clientId = `terms-signer-${randomUUID()}`;
      await prisma.oauthClient.create({ data: {
        id: clientId, clientId, name: 'Terms signer', type: 'web', public: false, tokenEndpointAuthMethod: 'client_secret_basic',
        grantTypes: ['authorization_code'], responseTypes: ['code'], scopes: ['openid', 'email', 'tinycloud:manage-key'],
      } });
      await prisma.oauthConsent.create({ data: { id: randomUUID(), userId, clientId, scopes: ['openid', 'email', 'tinycloud:manage-key'] } });
      const bearer = `terms-signer-token-${randomUUID()}`;
      await prisma.oauthAccessToken.create({ data: {
        id: randomUUID(), token: createHash('sha256').update(bearer).digest('base64url'), clientId, userId,
        scopes: ['tinycloud:manage-key'], createdAt: new Date(), expiresAt: new Date(Date.now() + 300_000),
      } });

      const refused = await sign({ authorization: `Bearer ${bearer}` });
      expect(refused.status, await refused.clone().text()).toBe(403);
      expect(await refused.json()).toMatchObject({ approved: false, code: 'terms_required' });

      expect((await accept(cookie)).status).toBe(200);
      expect(await (await sign({ authorization: `Bearer ${bearer}` })).text()).not.toContain('terms_required');
    });

    test('signing in the browser answers terms_required, so the page can send the account to the Terms', async () => {
      release(VERSION);
      const { cookie } = await signedIn();
      await expectTermsRequired(await sign({ cookie, origin: web }));
      expect((await accept(cookie)).status).toBe(200);
      expect(await (await sign({ cookie, origin: web })).text()).not.toContain('terms_required');
    });

    test('a refused MCP refresh leaves the web session as it was', async () => {
      release(null);
      const { cookie, userId } = await signedIn();
      const resource = 'https://mcp.tinycloud.xyz/mcp';
      const scope = 'openid email offline_access tinycloud:mcp';
      const { clientId } = await register(scope);
      const query = new URLSearchParams({
        client_id: clientId, response_type: 'code', redirect_uri: callback, scope, resource, state: 'state',
        code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256',
      });
      const consentUrl = new URL((await request(`${issuer}/oauth2/authorize?${query}`, {}, cookie)).headers.get('location')!, issuer);
      const approve = await json(`${issuer}/oauth2/consent`, { accept: true, oauth_query: consentUrl.searchParams.toString() }, cookie);
      const code = new URL((await approve.json() as { url: string }).url).searchParams.get('code')!;
      const exchanged = await form('/oauth2/token', {
        client_id: clientId, grant_type: 'authorization_code', code, redirect_uri: callback, code_verifier: verifier, resource,
      });
      expect(exchanged.status, await exchanged.clone().text()).toBe(200);
      const { refresh_token } = await exchanged.json() as { refresh_token: string };

      release(VERSION);
      const session = await prisma.session.findFirstOrThrow({ where: { userId } });
      const expiresAt = new Date(Date.now() + 3_600_000);
      await prisma.session.update({ where: { id: session.id }, data: { expiresAt } });
      const refused = await form('/oauth2/token', { client_id: clientId, grant_type: 'refresh_token', refresh_token, resource });
      expect(refused.status).toBe(400);
      expect(await refused.json()).toMatchObject({ error: 'invalid_grant', terms_url: TERMS_URL });
      expect((await prisma.session.findUniqueOrThrow({ where: { id: session.id } })).expiresAt).toEqual(expiresAt);
    });

    test('a session token records an acceptance only after a sign-in in the last 10 minutes', async () => {
      release(VERSION);
      const { bearer, userId } = await signedIn();
      await prisma.session.updateMany({ where: { userId }, data: { createdAt: new Date(Date.now() - 11 * 60_000) } });
      const response = await request(`${api}/api/account/terms/accept`, {
        method: 'POST', headers: { authorization: `Bearer ${bearer}`, origin: web, 'content-type': 'application/json' },
        body: JSON.stringify({ version: VERSION }),
      });
      expect(response.status).toBe(403);
      expect(await response.json()).toEqual({ error: 'terms_step_up' });
      expect(await rows(userId)).toEqual([]);
    });

    test('an acceptance cannot be deleted while its account exists, and goes with the account', async () => {
      release(VERSION);
      const { cookie, userId } = await signedIn();
      await accept(cookie);
      const [row] = await rows(userId);
      expect(await prisma.termsAcceptance.delete({ where: { id: row!.id } }).then(() => 'deleted', () => 'refused')).toBe('refused');
      expect(await rows(userId)).toEqual([row!]);
      await prisma.user.delete({ where: { id: userId } });
      expect(await rows(userId)).toEqual([]);
    });
  });

  describe('native renew', () => {
    // A native grant as PAR, approve and the code exchange leave it, with the app's session key.
    async function nativeGrant(userId: string) {
      const { clientId } = await register();
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      const x = publicKey.export({ format: 'jwk' }).x!;
      const sessionJkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })).digest('base64url');
      const token = `native-refresh-${randomUUID()}`;
      const grant = await prisma.tinyCloudNativeGrant.create({ data: {
        id: randomUUID(), userId, clientId, consentId: 'consent', consentGeneration: 1n, keyId: 'key', address: '0x1',
        sessionDid: 'did:key:z', sessionJwk: { kty: 'OKP', crv: 'Ed25519', x }, sessionJkt, spaceId: 'space',
        approvedPermissions: [], ttlSeconds: 3600, tinycloudHost: 'https://node.example.test',
        refreshTokenHash: credentialHash(token), absoluteExpiresAt: new Date(Date.now() + 86_400_000),
      } });
      const call = (operation: 'renew' | 'revoke') => {
        const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
        const header = encode({ typ: 'openkey-session-proof+jwt', alg: 'EdDSA', kid: sessionJkt });
        const payload = encode({
          jti: randomUUID().replaceAll('-', ''), iat: Math.floor(Date.now() / 1000), htm: 'POST',
          htu: `${issuer}${NATIVE_DELEGATION_ENDPOINT_PATHS[operation]}`, client_id: clientId, cred_hash: credentialHash(token),
        });
        const proof = `${header}.${payload}.${sign(null, Buffer.from(`${header}.${payload}`), privateKey).toString('base64url')}`;
        return request(`${issuer}${NATIVE_DELEGATION_ENDPOINT_PATHS[operation]}`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', [OPENKEY_SESSION_PROOF_HEADER]: proof },
          body: new URLSearchParams({ client_id: clientId, refresh_token: token }),
        });
      };
      return { grant, call };
    }
    const unchanged = (row: { refreshTokenHash: string | null; status: string; renewCount: number; revokedAt: Date | null }) =>
      ({ refreshTokenHash: row.refreshTokenHash, status: row.status, renewCount: row.renewCount, revokedAt: row.revokedAt });

    test('a renewal is refused with the Terms URL and the grant is kept as it was, until the account accepts', async () => {
      release(VERSION);
      const { cookie, userId } = await signedIn();
      const { grant, call } = await nativeGrant(userId);

      const refused = await call('renew');
      expect(refused.status).toBe(400);
      expect(await refused.json()).toEqual({
        error: 'invalid_grant', error_description: `Open ${TERMS_URL} to accept the Terms of Service.`, terms_url: TERMS_URL,
      });
      const after = await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: grant.id } });
      expect(unchanged(after)).toEqual(unchanged(grant));

      expect((await accept(cookie)).status).toBe(200);
      expect(await (await call('renew')).text()).not.toContain('terms_url');
    });

    test('revoking stays open before acceptance', async () => {
      release(VERSION);
      const { userId } = await signedIn();
      const { grant, call } = await nativeGrant(userId);
      const response = await call('revoke');
      expect(await response.clone().text()).not.toContain('terms_url');
      expect(response.status, await response.clone().text()).toBe(200);
      expect((await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: grant.id } })).status).not.toBe('ACTIVE');
    });

    test('an app disconnected before acceptance can no longer renew what it was granted, once the account accepts', async () => {
      release(VERSION);
      const { cookie, userId } = await signedIn();
      const { grant, call } = await nativeGrant(userId);
      await prisma.oauthConsent.create({ data: { id: randomUUID(), userId, clientId: grant.clientId, scopes: ['openid', 'tinycloud:delegation'] } });
      const disconnected = await request(`${api}/api/account/tinycloud-apps/${grant.clientId}`, {
        method: 'DELETE', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ confirmation: 'DISCONNECT' }),
      }, cookie);
      expect(disconnected.status, await disconnected.clone().text()).toBe(200);

      expect((await accept(cookie)).status).toBe(200);
      const renewed = await call('renew');
      expect(renewed.status).toBe(400);
      expect(await renewed.json()).not.toHaveProperty('terms_url');
      expect((await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: grant.id } })).status).not.toBe('ACTIVE');
    });
  });

  async function register(scope = 'openid email offline_access') {
    const registered = await request(`${issuer}/oauth2/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Terms regression', redirect_uris: [callback], token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], scope,
      }),
    });
    expect(registered.status, await registered.clone().text()).toBe(200);
    return { clientId: (await registered.json() as { client_id: string }).client_id, scope };
  }

  async function authorize(cookie: string, clientId: string, scope: string) {
    const query = new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: callback, scope, state: 'state',
      code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256',
    });
    const response = await request(`${issuer}/oauth2/authorize?${query}`, {}, cookie);
    expect(response.status, await response.clone().text()).toBe(302);
    return new URL(response.headers.get('location')!, issuer);
  }

  /** Authorize, consent and code exchange for a signed-in account that has nothing left to accept. */
  async function connect(cookie: string) {
    const { clientId, scope } = await register();
    const consentUrl = await authorize(cookie, clientId, scope);
    expect(consentUrl.pathname).toBe('/oauth/consent');
    const approve = await json(`${issuer}/oauth2/consent`, { accept: true, oauth_query: consentUrl.searchParams.toString() }, cookie);
    expect(approve.status, await approve.clone().text()).toBe(200);
    const code = new URL((await approve.json() as { url: string }).url).searchParams.get('code')!;
    const exchanged = await form('/oauth2/token', {
      client_id: clientId, grant_type: 'authorization_code', code, redirect_uri: callback, code_verifier: verifier,
    });
    expect(exchanged.status, await exchanged.clone().text()).toBe(200);
    return { clientId, tokens: await exchanged.json() as { access_token: string; refresh_token: string } };
  }

  describe('the OAuth provider', () => {
    test('authorize sends the account to the Terms screen; continue and consent are refused until it accepts', async () => {
      release(VERSION);
      const { cookie } = await signedIn();
      const { clientId, scope } = await register();
      const terms = await authorize(cookie, clientId, scope);
      expect(`${terms.origin}${terms.pathname}`).toBe(TERMS_URL);
      expect(terms.searchParams.get('sig')).toBeTruthy();
      const oauthQuery = terms.searchParams.toString();

      await expectTermsRequired(await json(`${issuer}/oauth2/continue`, { postLogin: true, oauth_query: oauthQuery }, cookie));
      await expectTermsRequired(await json(`${issuer}/oauth2/consent`, { accept: true, oauth_query: oauthQuery }, cookie));

      expect((await accept(cookie)).status).toBe(200);
      const resumed = await json(`${issuer}/oauth2/continue`, { postLogin: true, oauth_query: oauthQuery }, cookie);
      expect(resumed.status, await resumed.clone().text()).toBe(200);
      expect(new URL((await resumed.json() as { url: string }).url, issuer).pathname).toBe('/oauth/consent');
    });

    test('prompt=none gets interaction_required, not a code', async () => {
      release(VERSION);
      const { cookie } = await signedIn();
      const { clientId, scope } = await register();
      const query = new URLSearchParams({
        client_id: clientId, response_type: 'code', redirect_uri: callback, scope, state: 'state', prompt: 'none',
        code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256',
      });
      const response = await request(`${issuer}/oauth2/authorize?${query}`, {}, cookie);
      const location = new URL(response.headers.get('location')!, issuer);
      expect(location.searchParams.get('error')).toBe('interaction_required');
      expect(location.searchParams.get('code')).toBeNull();
    });

    test('a refresh and userinfo are refused, not revoked, until the account accepts', async () => {
      release(null);
      const { cookie, userId } = await signedIn();
      const { clientId, tokens } = await connect(cookie);
      release(VERSION);

      const refused = await form('/oauth2/token', { client_id: clientId, grant_type: 'refresh_token', refresh_token: tokens.refresh_token });
      expect(refused.status).toBe(400);
      expect(await refused.json()).toMatchObject({ error: 'invalid_grant', terms_url: TERMS_URL });
      expect(await prisma.oauthRefreshToken.findMany({ where: { userId, clientId }, select: { revoked: true } })).toEqual([{ revoked: null }]);
      const userinfo = () => request(`${issuer}/oauth2/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
      await expectTermsRequired(await userinfo());

      expect((await accept(cookie)).status).toBe(200);
      expect((await userinfo()).status).toBe(200);
      const refreshed = await form('/oauth2/token', { client_id: clientId, grant_type: 'refresh_token', refresh_token: tokens.refresh_token });
      expect(refreshed.status, await refreshed.clone().text()).toBe(200);
    });
  });

  test('a reviewer account is seeded with the current version at start and passes the gate', async () => {
    release(VERSION);
    const { userId } = await signedIn();
    await prisma.reviewerAccount.update({ where: { store: 'apple' }, data: { userId } });
    try {
      await initializeReviewers(prisma);
      await seedReviewerTerms(prisma);
      const seeded = await rows(userId);
      expect(seeded).toHaveLength(1);
      expect(seeded[0]).toMatchObject({ version: VERSION, textSha256: SHA, surface: 'reviewer_seed' });
      expect(await hasAcceptedTerms(prisma, userId)).toBe(true);
    } finally {
      await prisma.reviewerAccount.update({ where: { store: 'apple' }, data: { userId: null } });
    }
  });
}
