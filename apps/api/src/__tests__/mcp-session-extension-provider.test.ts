import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';

// API unit tests replace modules process-wide. Exercise the real provider and
// tracked database migrations in a separate process, as the other MCP provider
// tests do.
const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_MCP_OAUTH_TEST_CHILD !== '1') {
  test('an MCP refresh extends its authorizing session, capped at 30 days from sign-in', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_MCP_OAUTH_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'mcp-session-extension-isolated-test-secret',
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
  }, 240_000);
} else {
  const issuer = 'https://api.openkey.test/api/auth';
  const resource = 'https://mcp.tinycloud.xyz/mcp';
  const callback = 'https://chatgpt.com/connector_platform_oauth_redirect';
  const verifier = 'mcp-session-extension-pkce-verifier-0123456789012345';
  const DAY = 86_400_000;
  const ownerAddress = (n: number) => `0x${n.toString(16).padStart(40, '0')}`;
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let authOptions: { session?: { expiresIn?: number; updateAge?: number } };
  let secret: string;
  let cookieName: string;
  let counter = 0;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-mcp-session-extension-'));
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
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    const context = await authModule.auth.$context;
    secret = context.secret;
    cookieName = context.authCookies.sessionToken.name;
    authOptions = authModule.auth.options as typeof authOptions;
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  const call = (path: string, init: RequestInit = {}, cookie?: string) => app.fetch(new Request(`${issuer}${path}`, {
    ...init, headers: { ...(cookie ? { cookie, origin: 'https://openkey.test' } : {}), ...init.headers },
  }));
  const form = (path: string, values: Record<string, string>, headers: Record<string, string> = {}) => call(path, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(values),
  });
  const refresh = (clientId: string, token: string, extra: Record<string, string> = { resource }, headers: Record<string, string> = {}) =>
    form('/oauth2/token', { client_id: clientId, grant_type: 'refresh_token', refresh_token: token, ...extra }, headers);
  const basic = (client: string, clientSecret: string) => ({ authorization: `Basic ${Buffer.from(`${client}:${clientSecret}`).toString('base64')}` });

  /** A user with one signed-in session, and the cookie that carries it. */
  async function signedIn() {
    const n = ++counter;
    const userId = `ext-user-${n}`;
    const sessionId = `ext-session-${n}`;
    const token = randomUUID();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    await prisma.ethereumKey.create({ data: { id: `ext-key-${n}`, userId, address: ownerAddress(n), publicKey: '0x1', keyType: 'EXTERNAL' } });
    await prisma.session.create({ data: { id: sessionId, userId, token, expiresAt: new Date(Date.now() + 7 * DAY) } });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    return { userId, sessionId, cookie };
  }

  /** Sets how old the sign-in is and how long the session has left. */
  const age = (sessionId: string, ageDays: number, leftMs: number) =>
    prisma.session.update({ where: { id: sessionId }, data: { createdAt: new Date(Date.now() - ageDays * DAY), expiresAt: new Date(Date.now() + leftMs) } });
  const session = (sessionId: string) => prisma.session.findUniqueOrThrow({ where: { id: sessionId } });
  const near = (actual: Date, expectedMs: number, toleranceMs = 10_000) => Math.abs(actual.getTime() - expectedMs) <= toleranceMs;

  async function walk(clientId: string, cookie: string, exchangeHeaders: Record<string, string>) {
    const query = new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: callback, scope: 'openid email offline_access tinycloud:mcp', resource,
      state: 'state', code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256',
    });
    const authorized = await call(`/oauth2/authorize?${query}`, {}, cookie);
    expect(authorized.status, await authorized.clone().text()).toBe(302);
    const consentUrl = new URL(authorized.headers.get('location')!, issuer);
    const approve = await call('/oauth2/consent', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ accept: true, oauth_query: consentUrl.searchParams.toString() }),
    }, cookie);
    expect(approve.status, await approve.clone().text()).toBe(200);
    const code = new URL((await approve.json() as { url: string }).url).searchParams.get('code')!;
    const exchanged = await form('/oauth2/token', {
      client_id: clientId, grant_type: 'authorization_code', code, redirect_uri: callback, code_verifier: verifier, resource,
    }, exchangeHeaders);
    expect(exchanged.status, await exchanged.clone().text()).toBe(200);
    return await exchanged.json() as { access_token: string; refresh_token: string };
  }

  /** A public MCP app, registered dynamically and connected under the signed-in session. */
  async function connectMcp(cookie: string) {
    const registered = await call('/oauth2/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Session extension regression', redirect_uris: [callback], token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
        scope: 'openid email offline_access tinycloud:mcp',
      }),
    });
    expect(registered.status, await registered.clone().text()).toBe(200);
    const clientId = (await registered.json() as { client_id: string }).client_id;
    return { clientId, tokens: await walk(clientId, cookie, {}) };
  }

  /** A confidential MCP client with a stored (hashed) secret, connected under the signed-in session. */
  async function connectConfidential(cookie: string, clientSecret: string) {
    const { hashClientSecret } = await import('../services/resource-server');
    const clientId = `confidential-${++counter}`;
    await prisma.oauthClient.create({ data: {
      id: `row-${clientId}`, clientId, clientSecret: hashClientSecret(clientSecret), name: 'Confidential MCP app',
      redirectUris: [callback], scopes: ['openid', 'email', 'offline_access', 'tinycloud:mcp'], public: false, type: 'web',
      tokenEndpointAuthMethod: 'client_secret_basic', grantTypes: ['authorization_code', 'refresh_token'], responseTypes: ['code'],
    } });
    return { clientId, tokens: await walk(clientId, cookie, basic(clientId, clientSecret)) };
  }

  const refreshRows = (clientId: string) => prisma.oauthRefreshToken.findMany({ where: { clientId }, select: { revoked: true } });

  describe('extending the authorizing session', () => {
    test('the shared lifetime constants are the live auth options', async () => {
      const { SESSION_EXPIRES_IN_SECONDS, SESSION_UPDATE_AGE_SECONDS } = await import('../services/session-lifetime');
      expect(authOptions.session?.expiresIn).toBe(SESSION_EXPIRES_IN_SECONDS);
      expect(authOptions.session?.updateAge).toBe(SESSION_UPDATE_AGE_SECONDS);
    });

    test('a refresh on day 6 extends the session to six days from now', async () => {
      const { cookie, sessionId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      await age(sessionId, 6, DAY);
      const response = await refresh(clientId, tokens.refresh_token);
      expect(response.status, await response.clone().text()).toBe(200);
      expect(near((await session(sessionId)).expiresAt, Date.now() + 6 * DAY)).toBe(true);
    });

    test('a refresh on day 25 extends the session, capped at 30 days after sign-in', async () => {
      const { cookie, sessionId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      await age(sessionId, 25, 12 * 3_600_000);
      expect((await refresh(clientId, tokens.refresh_token)).status).toBe(200);
      const after = await session(sessionId);
      expect(after.expiresAt.getTime()).toBe(after.createdAt.getTime() + 30 * DAY);
    });

    test('a session 29 days old extends to the 30-day mark and no further', async () => {
      const { cookie, sessionId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      await age(sessionId, 29, 3_600_000);
      expect((await refresh(clientId, tokens.refresh_token)).status).toBe(200);
      const after = await session(sessionId);
      expect(after.expiresAt.getTime()).toBe(after.createdAt.getTime() + 30 * DAY);
      expect(after.expiresAt.getTime()).toBeLessThan(Date.now() + 2 * DAY);
    });

    test('a session 31 days old (kept alive by web use) is not extended and the refresh is invalid_grant, unrotated', async () => {
      const { cookie, sessionId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      await age(sessionId, 31, 3_600_000);
      const before = await session(sessionId);
      const response = await refresh(clientId, tokens.refresh_token);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: 'invalid_grant' });
      expect((await session(sessionId)).expiresAt.getTime()).toBe(before.expiresAt.getTime());
      expect(await refreshRows(clientId)).toEqual([{ revoked: null }]);
    });

    test('an expired session is not revived and a signed-out one is not recreated', async () => {
      const first = await signedIn();
      const app1 = await connectMcp(first.cookie);
      await age(first.sessionId, 3, -1000);
      const expired = (await session(first.sessionId)).expiresAt.getTime();
      expect((await refresh(app1.clientId, app1.tokens.refresh_token)).status).toBe(400);
      expect((await session(first.sessionId)).expiresAt.getTime()).toBe(expired);

      const second = await signedIn();
      const app2 = await connectMcp(second.cookie);
      expect((await call('/sign-out', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }, second.cookie)).status).toBe(200);
      const response = await refresh(app2.clientId, app2.tokens.refresh_token);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: 'invalid_grant' });
      expect(await prisma.session.count({ where: { id: second.sessionId } })).toBe(0);
    });

    test('after Disconnect (consent and tokens removed) the refresh is invalid_grant and nothing is extended', async () => {
      const { cookie, userId, sessionId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      await age(sessionId, 6, DAY);
      const before = (await session(sessionId)).expiresAt.getTime();
      await prisma.$transaction([
        prisma.oauthConsent.deleteMany({ where: { userId, clientId } }),
        prisma.oauthAccessToken.deleteMany({ where: { userId, clientId } }),
        prisma.oauthRefreshToken.deleteMany({ where: { userId, clientId } }),
      ]);
      expect((await refresh(clientId, tokens.refresh_token)).status).toBe(400);
      expect((await session(sessionId)).expiresAt.getTime()).toBe(before);
    });

    test('an access token cannot extend a session', async () => {
      const { cookie, sessionId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      await age(sessionId, 6, DAY);
      const before = (await session(sessionId)).expiresAt.getTime();
      const response = await refresh(clientId, tokens.access_token);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: 'invalid_grant' });
      expect((await session(sessionId)).expiresAt.getTime()).toBe(before);
    });

    test('another client\'s refresh extends only its own session, and a token presented by another client extends nothing', async () => {
      const mine = await signedIn();
      const appA = await connectMcp(mine.cookie);
      const other = await signedIn();
      const appB = await connectMcp(other.cookie);
      await age(mine.sessionId, 6, DAY);
      await age(other.sessionId, 6, DAY);
      const mineBefore = (await session(mine.sessionId)).expiresAt.getTime();

      expect((await refresh(appB.clientId, appB.tokens.refresh_token)).status).toBe(200);
      expect((await session(mine.sessionId)).expiresAt.getTime()).toBe(mineBefore);
      expect(near((await session(other.sessionId)).expiresAt, Date.now() + 6 * DAY)).toBe(true);

      const crossed = await refresh(appB.clientId, appA.tokens.refresh_token);
      expect(crossed.status).toBe(400);
      expect(await crossed.json()).toMatchObject({ error: 'invalid_client' });
      expect((await session(mine.sessionId)).expiresAt.getTime()).toBe(mineBefore);
    });

    test('a confidential client extends only with its secret, as the provider checks it', async () => {
      const { cookie, sessionId } = await signedIn();
      const { clientId, tokens } = await connectConfidential(cookie, 'the-right-secret');
      await age(sessionId, 6, DAY);
      const before = (await session(sessionId)).expiresAt.getTime();

      const wrong = await refresh(clientId, tokens.refresh_token, { resource }, basic(clientId, 'a-wrong-secret'));
      expect(wrong.status).toBe(401);
      expect(await wrong.json()).toMatchObject({ error: 'invalid_client' });
      const none = await refresh(clientId, tokens.refresh_token);
      expect(none.status).toBe(400);
      expect(await none.json()).toMatchObject({ error: 'invalid_client' });
      expect((await session(sessionId)).expiresAt.getTime()).toBe(before);
      expect(await refreshRows(clientId)).toEqual([{ revoked: null }]);

      const right = await refresh(clientId, tokens.refresh_token, { resource }, basic(clientId, 'the-right-secret'));
      expect(right.status, await right.clone().text()).toBe(200);
      expect(near((await session(sessionId)).expiresAt, Date.now() + 6 * DAY)).toBe(true);

      await age(sessionId, 6, DAY);
      const next = (await right.json() as { refresh_token: string }).refresh_token;
      const viaBody = await refresh(clientId, next, { resource, client_secret: 'the-right-secret' });
      expect(viaBody.status, await viaBody.clone().text()).toBe(200);
      expect(near((await session(sessionId)).expiresAt, Date.now() + 6 * DAY)).toBe(true);
    });

    test('a disabled client extends nothing', async () => {
      const { cookie, sessionId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      await age(sessionId, 6, DAY);
      const before = (await session(sessionId)).expiresAt.getTime();
      await prisma.oauthClient.update({ where: { clientId }, data: { disabled: true } });
      expect((await refresh(clientId, tokens.refresh_token)).status).toBe(400);
      expect((await session(sessionId)).expiresAt.getTime()).toBe(before);
    });

    test('parallel refreshes of apps sharing one session extend it once, never past the limits', async () => {
      const { cookie, sessionId } = await signedIn();
      const first = await connectMcp(cookie);
      const second = await connectMcp(cookie);

      await age(sessionId, 6, DAY);
      const both = await Promise.all([refresh(first.clientId, first.tokens.refresh_token), refresh(second.clientId, second.tokens.refresh_token)]);
      expect(both.map((response) => response.status)).toEqual([200, 200]);
      expect(near((await session(sessionId)).expiresAt, Date.now() + 6 * DAY)).toBe(true);

      await age(sessionId, 25, 3_600_000);
      const next = await Promise.all(both.map(async (response) => (await response.json() as { refresh_token: string }).refresh_token));
      const again = await Promise.all([refresh(first.clientId, next[0]!), refresh(second.clientId, next[1]!)]);
      expect(again.map((response) => response.status)).toEqual([200, 200]);
      const after = await session(sessionId);
      expect(after.expiresAt.getTime()).toBe(after.createdAt.getTime() + 30 * DAY);
    });

    test('a sign-out that races a refresh wins: the session ends and stays gone', async () => {
      for (let round = 0; round < 4; round++) {
        const { cookie, sessionId } = await signedIn();
        const { clientId, tokens } = await connectMcp(cookie);
        await age(sessionId, 6, DAY);
        const [out, refreshed] = await Promise.all([
          call('/sign-out', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }, cookie),
          refresh(clientId, tokens.refresh_token),
        ]);
        expect(out.status).toBe(200);
        expect([200, 400]).toContain(refreshed.status);
        expect(await prisma.session.count({ where: { id: sessionId } }), `round ${round}`).toBe(0);
        const later = await refresh(clientId, tokens.refresh_token);
        expect(later.status).toBe(400);
        expect(await later.json()).toMatchObject({ error: 'invalid_grant' });
      }
    });

    test('web sign-in is unchanged: a web use after an MCP refresh renews to seven days and re-sends the cookie', async () => {
      const { cookie, sessionId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      await age(sessionId, 6, DAY);
      expect((await refresh(clientId, tokens.refresh_token)).status).toBe(200);
      const extended = (await session(sessionId)).expiresAt;
      expect(near(extended, Date.now() + 6 * DAY)).toBe(true);

      const web = await call('/get-session', {}, cookie);
      expect(web.status).toBe(200);
      const maxAge = Number(/Max-Age=(\d+)/i.exec(web.headers.get('set-cookie') ?? '')?.[1]);
      expect(maxAge).toBeGreaterThan(7 * 86_400 - 30);
      expect(maxAge).toBeLessThanOrEqual(7 * 86_400);
      expect(near((await session(sessionId)).expiresAt, Date.now() + 7 * DAY)).toBe(true);
    });

    test('the update does not depend on the database session time zone', async () => {
      try {
        for (const zone of ['Pacific/Auckland', 'America/Los_Angeles']) {
          await prisma.$executeRawUnsafe(`SET TIME ZONE '${zone}'`);
          const { cookie, sessionId } = await signedIn();
          const { clientId, tokens } = await connectMcp(cookie);

          await age(sessionId, 6, DAY);
          const renewed = await refresh(clientId, tokens.refresh_token);
          expect(renewed.status, `${zone} ${await renewed.clone().text()}`).toBe(200);
          expect(near((await session(sessionId)).expiresAt, Date.now() + 6 * DAY), zone).toBe(true);

          await age(sessionId, 29, 3_600_000);
          const next = (await renewed.json() as { refresh_token: string }).refresh_token;
          expect((await refresh(clientId, next)).status, zone).toBe(200);
          const capped = await session(sessionId);
          expect(capped.expiresAt.getTime(), zone).toBe(capped.createdAt.getTime() + 30 * DAY);
        }
      } finally {
        await prisma.$executeRawUnsafe('RESET TIME ZONE');
      }
    });
  });
}
