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
// tracked database migrations in a separate process, as the MCP registration
// test does.
const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_MCP_OAUTH_TEST_CHILD !== '1') {
  test('an MCP refresh is refused, unrotated, once its authorizing session has ended', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_MCP_OAUTH_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'mcp-session-guard-isolated-test-secret',
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
  }, 180_000);
} else {
  const issuer = 'https://api.openkey.test/api/auth';
  const resource = 'https://mcp.tinycloud.xyz/mcp';
  const callback = 'https://chatgpt.com/connector_platform_oauth_redirect';
  const verifier = 'mcp-session-guard-pkce-verifier-0123456789012345678';
  // A distinct, valid-looking owner address per test user.
  const ownerAddress = (n: number) => `0x${n.toString(16).padStart(40, '0')}`;
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let secret: string;
  let cookieName: string;
  let counter = 0;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-mcp-session-guard-'));
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
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  const call = (path: string, init: RequestInit = {}, cookie?: string) => app.fetch(new Request(`${issuer}${path}`, {
    ...init, headers: { ...(cookie ? { cookie, origin: 'https://openkey.test' } : {}), ...init.headers },
  }));
  const form = (path: string, values: Record<string, string>) => call(path, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(values),
  });
  const refresh = (clientId: string, token: string, extra: Record<string, string> = { resource }) =>
    form('/oauth2/token', { client_id: clientId, grant_type: 'refresh_token', refresh_token: token, ...extra });

  /** A user with one signed-in session, and the cookie that carries it. */
  async function signedIn() {
    const n = ++counter;
    const userId = `guard-user-${n}`;
    const sessionId = `guard-session-${n}`;
    const token = randomUUID();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    await prisma.ethereumKey.create({ data: { id: `guard-key-${n}`, userId, address: ownerAddress(n), publicKey: '0x1', keyType: 'EXTERNAL' } });
    await prisma.session.create({ data: { id: sessionId, userId, token, expiresAt: new Date(Date.now() + 7 * 86_400_000) } });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    return { userId, sessionId, cookie };
  }

  /** Registers an app and walks authorize, consent and code exchange for the signed-in user. */
  async function connect(cookie: string, scope: string, withResource: boolean) {
    const registered = await call('/oauth2/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Session guard regression', redirect_uris: [callback], token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], scope,
      }),
    });
    expect(registered.status, await registered.clone().text()).toBe(200);
    const clientId = (await registered.json() as { client_id: string }).client_id;
    const query = new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: callback, scope, ...(withResource ? { resource } : {}),
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
      client_id: clientId, grant_type: 'authorization_code', code, redirect_uri: callback, code_verifier: verifier,
      ...(withResource ? { resource } : {}),
    });
    expect(exchanged.status, await exchanged.clone().text()).toBe(200);
    return { clientId, tokens: await exchanged.json() as { access_token: string; refresh_token: string } };
  }
  const connectMcp = (cookie: string) => connect(cookie, 'openid email offline_access tinycloud:mcp', true);

  const refreshRows = (clientId: string) => prisma.oauthRefreshToken.findMany({ where: { clientId }, select: { revoked: true } });
  async function expectRefused(clientId: string, token: string, extra?: Record<string, string>) {
    const response = await refresh(clientId, token, extra);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: 'invalid_grant' });
    return response;
  }

  describe('MCP refresh and the authorizing session', () => {
    test('a live session refreshes and rotates as before', async () => {
      const { cookie } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      const response = await refresh(clientId, tokens.refresh_token);
      expect(response.status, await response.clone().text()).toBe(200);
      const body = await response.json() as { access_token: string; refresh_token: string };
      expect(body.refresh_token).not.toBe(tokens.refresh_token);
      expect((await refreshRows(clientId)).map((row) => row.revoked !== null).sort()).toEqual([false, true]);
    });

    test('an expired session is refused with invalid_grant and the refresh token stays unrotated and usable once the session is live', async () => {
      const { cookie, sessionId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      await prisma.session.update({ where: { id: sessionId }, data: { expiresAt: new Date(Date.now() - 1000) } });
      expect((await expectRefused(clientId, tokens.refresh_token)).headers.get('cache-control')).toBe('no-store');
      await expectRefused(clientId, tokens.refresh_token, {});
      expect(await refreshRows(clientId)).toEqual([{ revoked: null }]);
      await prisma.session.update({ where: { id: sessionId }, data: { expiresAt: new Date(Date.now() + 3_600_000) } });
      expect((await refresh(clientId, tokens.refresh_token)).status).toBe(200);
    });

    test('after sign-out the refresh is invalid_grant and nothing is rotated', async () => {
      const { cookie, sessionId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      const out = await call('/sign-out', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }, cookie);
      expect(out.status).toBe(200);
      expect(await prisma.session.count({ where: { id: sessionId } })).toBe(0);
      await expectRefused(clientId, tokens.refresh_token);
      expect(await refreshRows(clientId)).toEqual([{ revoked: null }]);
    });

    test('after Disconnect (consent and token rows removed) the refresh is invalid_grant', async () => {
      const { cookie, userId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      // What the account page Disconnect does to the rows; the route itself ships separately.
      await prisma.$transaction([
        prisma.oauthConsent.deleteMany({ where: { userId, clientId } }),
        prisma.oauthAccessToken.deleteMany({ where: { userId, clientId } }),
        prisma.oauthRefreshToken.deleteMany({ where: { userId, clientId } }),
      ]);
      await expectRefused(clientId, tokens.refresh_token);
    });

    test('a refresh row without an authorizing session is refused', async () => {
      const { cookie, userId } = await signedIn();
      const { clientId, tokens } = await connectMcp(cookie);
      await prisma.oauthRefreshToken.updateMany({ where: { userId, clientId }, data: { sessionId: null } });
      await expectRefused(clientId, tokens.refresh_token);
    });

    test('another user\'s live session does not keep this token alive', async () => {
      const mine = await signedIn();
      const { clientId, tokens } = await connectMcp(mine.cookie);
      await signedIn();
      await prisma.session.delete({ where: { id: mine.sessionId } });
      await expectRefused(clientId, tokens.refresh_token);
    });

    test('a token presented by another client is the provider\'s call, not the guard\'s', async () => {
      const mine = await signedIn();
      const { tokens } = await connectMcp(mine.cookie);
      const other = await signedIn();
      const { clientId: otherClient } = await connectMcp(other.cookie);
      await prisma.session.delete({ where: { id: mine.sessionId } });
      const response = await refresh(otherClient, tokens.refresh_token);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: 'invalid_client' });
    });

    test('malformed or unknown refresh tokens get the provider\'s 400, never a server error', async () => {
      const { cookie } = await signedIn();
      const { clientId } = await connectMcp(cookie);
      for (const token of ['', 'not-a-token', 'a'.repeat(5000), 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmb28ifQ.invalid']) {
        const response = await refresh(clientId, token);
        expect(response.status, token.slice(0, 20)).toBe(400);
        expect(await response.json()).toMatchObject({ error: 'invalid_grant' });
      }
    });

    test('a refresh token without the MCP scope keeps today\'s behaviour, even with the session gone', async () => {
      const { cookie, sessionId } = await signedIn();
      const { clientId, tokens } = await connect(cookie, 'openid email offline_access', false);
      await prisma.session.delete({ where: { id: sessionId } });
      const response = await refresh(clientId, tokens.refresh_token, {});
      expect(response.status, await response.clone().text()).toBe(200);
      expect(await response.json()).toHaveProperty('refresh_token');
    });
  });
}
