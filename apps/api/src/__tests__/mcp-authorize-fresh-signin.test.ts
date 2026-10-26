import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { serializeSignedCookie } from 'better-call';
import { decodeJwt } from 'jose';
import type { PrismaClient } from '@openkey/db';

// API unit tests replace modules process-wide. Exercise the real provider and
// tracked database migrations in a separate process, as the other MCP provider
// tests do.
const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_MCP_OAUTH_TEST_CHILD !== '1') {
  test('a new MCP connection on a sign-in 23 days old or older needs a fresh sign-in first', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_MCP_OAUTH_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'mcp-authorize-fresh-signin-isolated-test-secret',
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
  const verifier = 'mcp-authorize-fresh-signin-pkce-verifier-0123456789';
  const MCP_SCOPES = 'openid email offline_access tinycloud:mcp';
  const DAY = 86_400_000;
  const ownerAddress = (n: number) => `0x${n.toString(16).padStart(40, '0')}`;
  // The development sign-in code for this address (auth.ts `generateOTP`).
  const DEV_EMAIL = 'test@openkey.dev';
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let secret: string;
  let cookieName: string;
  let counter = 0;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-mcp-fresh-signin-'));
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
  const json = (path: string, body: unknown, cookie?: string) => call(path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  }, cookie);
  const form = (path: string, values: Record<string, string>) => call(path, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(values),
  });

  /** A user whose web sign-in began `ageMs` ago and still has two days left. */
  async function signedIn(ageMs: number, email?: string) {
    const n = ++counter;
    const userId = `fresh-user-${n}`;
    const sessionId = `fresh-session-${n}`;
    const token = randomUUID();
    await prisma.user.create({ data: { id: userId, email: email ?? `${userId}@example.test`, name: userId, emailVerified: true } });
    await prisma.ethereumKey.create({ data: { id: `fresh-key-${n}`, userId, address: ownerAddress(n), publicKey: '0x1', keyType: 'EXTERNAL' } });
    await prisma.session.create({ data: { id: sessionId, userId, token, createdAt: new Date(Date.now() - ageMs), expiresAt: new Date(Date.now() + 2 * DAY) } });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    return { userId, sessionId, cookie };
  }

  async function register(scope: string) {
    const registered = await call('/oauth2/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Fresh sign-in regression', redirect_uris: [callback], token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], scope,
      }),
    });
    expect(registered.status, await registered.clone().text()).toBe(200);
    return (await registered.json() as { client_id: string }).client_id;
  }

  /** An authorize request; `scope: null` sends none, so the provider uses the client's own. */
  async function authorize(cookie: string, clientId: string, scope: string | null, extra: Record<string, string> = {}) {
    const query = new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: callback, ...(scope === null ? {} : { scope }), resource,
      state: 'state', code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256', ...extra,
    });
    const response = await call(`/oauth2/authorize?${query}`, {}, cookie);
    expect(response.status, await response.clone().text()).toBe(302);
    return new URL(response.headers.get('location')!, issuer);
  }
  const isConsentPage = (url: URL) => url.origin + url.pathname === 'https://openkey.test/oauth/consent';
  const isLoginPage = (url: URL) => url.origin + url.pathname === 'https://openkey.test/auth/login';
  const codes = () => prisma.verification.count();

  describe('a new MCP connection and the age of the sign-in', () => {
    test('a sign-in 22 days old proceeds to consent as before', async () => {
      const { cookie } = await signedIn(22 * DAY);
      const clientId = await register(MCP_SCOPES);
      expect(isConsentPage(await authorize(cookie, clientId, MCP_SCOPES))).toBe(true);
    });

    test('a sign-in 24 days old is sent to the login page with the login prompt, and no code is issued', async () => {
      const { cookie, userId } = await signedIn(24 * DAY);
      const clientId = await register(MCP_SCOPES);
      const before = await codes();
      const target = await authorize(cookie, clientId, MCP_SCOPES);
      expect(isLoginPage(target)).toBe(true);
      expect(target.searchParams.get('prompt')).toBe('login');
      expect(target.searchParams.get('client_id')).toBe(clientId);
      expect(target.searchParams.get('sig')).toBeTruthy();
      expect(target.searchParams.has('code')).toBe(false);
      expect(await codes()).toBe(before);
      expect(await prisma.oauthConsent.count({ where: { userId, clientId } })).toBe(0);
    });

    test('a request that names no scope uses the client\'s own, so an MCP client is held to the same rule', async () => {
      const { cookie } = await signedIn(24 * DAY);
      const clientId = await register(MCP_SCOPES);
      expect(isLoginPage(await authorize(cookie, clientId, null))).toBe(true);
    });

    test('a sign-in 24 days old proceeds when the request does not ask for the MCP scope', async () => {
      const { cookie } = await signedIn(24 * DAY);
      const clientId = await register('openid email');
      expect(isConsentPage(await authorize(cookie, clientId, 'openid email'))).toBe(true);
      // The same MCP-capable client, asking for less, is not held either.
      const mcpClient = await register(MCP_SCOPES);
      expect(isConsentPage(await authorize(cookie, mcpClient, 'openid email'))).toBe(true);
    });

    test('the limit is 23 days, inclusive: a minute under proceeds and a minute over needs a fresh sign-in', async () => {
      const under = await signedIn(23 * DAY - 60_000);
      const over = await signedIn(23 * DAY + 60_000);
      const clientId = await register(MCP_SCOPES);
      expect(isConsentPage(await authorize(under.cookie, clientId, MCP_SCOPES))).toBe(true);
      expect(isLoginPage(await authorize(over.cookie, clientId, MCP_SCOPES))).toBe(true);
    });

    test('a request that already asks for consent gets login added in front, and one that already asks for login is left as it is', async () => {
      const { cookie } = await signedIn(24 * DAY);
      const clientId = await register(MCP_SCOPES);
      const consent = await authorize(cookie, clientId, MCP_SCOPES, { prompt: 'consent' });
      expect(isLoginPage(consent)).toBe(true);
      expect(consent.searchParams.get('prompt')).toBe('login consent');
      const login = await authorize(cookie, clientId, MCP_SCOPES, { prompt: 'login' });
      expect(isLoginPage(login)).toBe(true);
      expect(login.searchParams.get('prompt')).toBe('login');
    });

    test('after a fresh sign-in the flow completes on the new session; nothing is issued on the old sign-in', async () => {
      const old = await signedIn(24 * DAY, DEV_EMAIL);
      const clientId = await register(MCP_SCOPES);
      const login = await authorize(old.cookie, clientId, MCP_SCOPES);
      expect(isLoginPage(login)).toBe(true);
      const oldBefore = await prisma.session.findUniqueOrThrow({ where: { id: old.sessionId } });

      // Sign in again the way the login page does, carrying the signed request.
      expect((await json('/email-otp/send-verification-otp', { email: DEV_EMAIL, type: 'sign-in' })).status).toBe(200);
      const signedInAgain = await json('/sign-in/email-otp', { email: DEV_EMAIL, otp: '000000', oauth_query: login.searchParams.toString() });
      expect(signedInAgain.status, await signedInAgain.clone().text()).toBe(200);
      const setCookie = signedInAgain.headers.get('set-cookie') ?? '';
      const fresh = new RegExp(`${cookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=([^;]+)`).exec(setCookie);
      expect(fresh, setCookie).toBeTruthy();
      const newCookie = `${cookieName}=${fresh![1]}`;
      const sessions = await prisma.session.findMany({ where: { userId: old.userId }, orderBy: { createdAt: 'asc' } });
      expect(sessions).toHaveLength(2);
      const created = sessions[1]!;
      expect(created.id).not.toBe(old.sessionId);
      expect(Date.now() - created.createdAt.getTime()).toBeLessThan(60_000);

      // The sign-in answer carries the resumed request: consent on the new session.
      const resumed = new URL(((await signedInAgain.json()) as { url?: string }).url ?? '', issuer);
      expect(isConsentPage(resumed), resumed.href).toBe(true);
      const approve = await json('/oauth2/consent', { accept: true, oauth_query: resumed.searchParams.toString() }, newCookie);
      expect(approve.status, await approve.clone().text()).toBe(200);
      const code = new URL((await approve.json() as { url: string }).url).searchParams.get('code')!;
      const exchanged = await form('/oauth2/token', {
        client_id: clientId, grant_type: 'authorization_code', code, redirect_uri: callback, code_verifier: verifier, resource,
      });
      expect(exchanged.status, await exchanged.clone().text()).toBe(200);
      const tokens = await exchanged.json() as { access_token: string };
      expect(decodeJwt(tokens.access_token).sid).toBe(created.id);

      // Nothing was issued on the old sign-in: every refresh token of this connection belongs to the new session.
      const refreshRows = await prisma.oauthRefreshToken.findMany({ where: { clientId }, select: { sessionId: true } });
      expect(refreshRows.length).toBeGreaterThan(0);
      expect(refreshRows.every((row) => row.sessionId === created.id)).toBe(true);
      // The old session is still the same sign-in and still ends at the absolute cap at the latest. (Any web request,
      // this authorize included, renews it the usual way; that renewal is capped and this path adds none.)
      const oldAfter = await prisma.session.findUniqueOrThrow({ where: { id: old.sessionId } });
      expect(oldAfter.createdAt.getTime()).toBe(oldBefore.createdAt.getTime());
      expect(oldAfter.expiresAt.getTime()).toBeLessThanOrEqual(oldAfter.createdAt.getTime() + 30 * DAY);
    });
  });
}
