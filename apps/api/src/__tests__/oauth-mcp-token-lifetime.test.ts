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

// TC-1366 (B): an access token issued for the hosted MCP resources lasts longer than the 5-minute default; every
// other audience keeps 5 minutes. The real provider and tracked migrations run in a separate process, as the other
// OAuth tests do, because API unit tests replace modules process-wide.
const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_MCP_LIFETIME_TEST_CHILD !== '1') {
  test('MCP access token lifetime through the real provider', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_MCP_LIFETIME_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'mcp-lifetime-isolated-test-secret',
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
  }, 120_000);
} else {
  const issuer = 'https://api.openkey.test/api/auth';
  const MCP_RESOURCES = ['https://mcp.tinycloud.xyz/mcp', 'https://mcp.tinycloud.xyz/chatgpt/mcp'] as const;
  const OPENKEY_AUDIENCE = 'https://api.openkey.test';
  const callback = 'https://chatgpt.com/connector_platform_oauth_redirect';
  const verifier = 'mcp-lifetime-pkce-verifier-0123456789012345678901';
  const FIVE_MINUTES = 300;
  const TWELVE_HOURS = 12 * 3600;
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookie: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-mcp-lifetime-'));
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
    await prisma.user.create({ data: { id: 'life-owner', email: 'life-owner@example.test', name: 'Owner', emailVerified: true } });
    await prisma.ethereumKey.create({ data: {
      id: 'life-owner-key', userId: 'life-owner', address: '0x31d40B62C395B9418C4198363619B11c65cD406F', publicKey: '0x1', keyType: 'EXTERNAL',
    } });
    const sessionToken = randomUUID();
    await prisma.session.create({ data: {
      id: 'life-owner-session', userId: 'life-owner', token: sessionToken, expiresAt: new Date(Date.now() + 3_600_000),
    } });
    const context = await authModule.auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  const call = (path: string, init: RequestInit = {}, authenticated = false) =>
    app.fetch(new Request(`${issuer}${path}`, { ...init, headers: { ...(authenticated ? { cookie } : {}), ...init.headers } }));
  const form = { 'content-type': 'application/x-www-form-urlencoded' };

  async function register() {
    const response = await call('/oauth2/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'MCP lifetime', redirect_uris: [callback], token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
      }),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    return (await response.json() as { client_id: string }).client_id;
  }

  // Sign in as the owner and approve; returns the code. `resource` undefined asks for no audience at all.
  async function authorizeCode(scope: string, resource: string | undefined) {
    const clientId = await register();
    const query = new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: callback, scope, state: 's',
      code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256',
      ...(resource === undefined ? {} : { resource }),
    });
    const consentRedirect = await call(`/oauth2/authorize?${query}`, {}, true);
    expect(consentRedirect.status, await consentRedirect.clone().text()).toBe(302);
    const consentUrl = new URL(consentRedirect.headers.get('location')!, issuer);
    const approve = await call('/oauth2/consent', {
      method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://openkey.test' },
      body: JSON.stringify({ accept: true, oauth_query: consentUrl.searchParams.toString() }),
    }, true);
    expect(approve.status, await approve.clone().text()).toBe(200);
    const code = new URL((await approve.json() as { url: string }).url).searchParams.get('code')!;
    return { clientId, code };
  }

  const exchange = (clientId: string, code: string, resource: string | undefined) => call('/oauth2/token', {
    method: 'POST', headers: form,
    body: new URLSearchParams({
      client_id: clientId, grant_type: 'authorization_code', code, redirect_uri: callback, code_verifier: verifier,
      ...(resource === undefined ? {} : { resource }),
    }),
  });

  async function issue(scope: string, resource: string | undefined) {
    const { clientId, code } = await authorizeCode(scope, resource);
    const exchanged = await exchange(clientId, code, resource);
    expect(exchanged.status, await exchanged.clone().text()).toBe(200);
    const tokens = await exchanged.json() as { access_token: string; refresh_token?: string; expires_in: number };
    return { clientId, tokens };
  }

  async function refresh(clientId: string, refreshToken: string, resource: string | undefined) {
    const response = await call('/oauth2/token', {
      method: 'POST', headers: form,
      body: new URLSearchParams({
        client_id: clientId, grant_type: 'refresh_token', refresh_token: refreshToken,
        ...(resource === undefined ? {} : { resource }),
      }),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    return await response.json() as { access_token: string; expires_in: number };
  }

  const lifetimeOf = (jwt: string) => {
    const { exp, iat } = decodeJwt(jwt);
    return exp! - iat!;
  };

  describe('access token lifetime by audience', () => {
    test.each(MCP_RESOURCES)('%s: the code exchange and every refresh issue a 12 hour token', async (resource) => {
      const { clientId, tokens } = await issue('openid email offline_access tinycloud:mcp', resource);
      expect(tokens.expires_in).toBe(TWELVE_HOURS);
      expect(lifetimeOf(tokens.access_token)).toBe(TWELVE_HOURS);
      const renewed = await refresh(clientId, tokens.refresh_token!, resource);
      expect(renewed.expires_in).toBe(TWELVE_HOURS);
      expect(lifetimeOf(renewed.access_token)).toBe(TWELVE_HOURS);
    });

    test('the refresh token keeps its own lifetime of 7 days; only the access token is longer', async () => {
      const { clientId, tokens } = await issue('openid email offline_access tinycloud:mcp', MCP_RESOURCES[0]);
      const row = await prisma.oauthRefreshToken.findFirst({ where: { clientId }, orderBy: { createdAt: 'desc' } });
      const seconds = (row!.expiresAt!.getTime() - row!.createdAt.getTime()) / 1000;
      expect(Math.round(seconds)).toBe(7 * 24 * 3600);
      expect(tokens.refresh_token).toBeTruthy();
    });

    test('a token for any other audience keeps the 5 minute default, at issue and on refresh', async () => {
      const { clientId, tokens } = await issue('openid email offline_access', OPENKEY_AUDIENCE);
      expect(tokens.expires_in).toBe(FIVE_MINUTES);
      expect(lifetimeOf(tokens.access_token)).toBe(FIVE_MINUTES);
      const renewed = await refresh(clientId, tokens.refresh_token!, OPENKEY_AUDIENCE);
      expect(renewed.expires_in).toBe(FIVE_MINUTES);
    });

    test('a token with no audience keeps the 5 minute default', async () => {
      const { tokens } = await issue('openid email', undefined);
      expect(tokens.expires_in).toBe(FIVE_MINUTES);
    });

    test('an MCP token is not extended by asking for another audience on refresh, nor a default one by asking for MCP', async () => {
      const mcp = await issue('openid email offline_access tinycloud:mcp', MCP_RESOURCES[0]);
      // The lifetime follows the audience of THIS request, so a refresh that names the OpenKey audience is short.
      expect((await refresh(mcp.clientId, mcp.tokens.refresh_token!, OPENKEY_AUDIENCE)).expires_in).toBe(FIVE_MINUTES);
      const plain = await issue('openid email offline_access', OPENKEY_AUDIENCE);
      expect((await refresh(plain.clientId, plain.tokens.refresh_token!, undefined)).expires_in).toBe(FIVE_MINUTES);
    });
  });

  describe('concurrent requests', () => {
    // The lifetime is read from per-request context while the provider reads one shared options object, so requests in
    // flight together must not see each other's audience.
    test('interleaved MCP and OpenKey-audience requests each get their own lifetime', async () => {
      const wanted = [MCP_RESOURCES[0], OPENKEY_AUDIENCE, MCP_RESOURCES[1], OPENKEY_AUDIENCE, MCP_RESOURCES[0], OPENKEY_AUDIENCE, MCP_RESOURCES[1], OPENKEY_AUDIENCE];
      const prepared = [];
      for (const resource of wanted) {
        prepared.push({ resource, ...(await authorizeCode('openid email offline_access' + (resource === OPENKEY_AUDIENCE ? '' : ' tinycloud:mcp'), resource)) });
      }
      const answers = await Promise.all(prepared.map(async ({ resource, clientId, code }) => {
        const response = await exchange(clientId, code, resource);
        expect(response.status, await response.clone().text()).toBe(200);
        const tokens = await response.json() as { access_token: string; refresh_token: string; expires_in: number };
        return { resource, clientId, tokens };
      }));
      const expected = (resource: string) => (resource === OPENKEY_AUDIENCE ? FIVE_MINUTES : TWELVE_HOURS);
      for (const { resource, tokens } of answers) {
        expect(tokens.expires_in, resource).toBe(expected(resource));
        expect(lifetimeOf(tokens.access_token), resource).toBe(expected(resource));
      }
      const renewed = await Promise.all(answers.map(async ({ resource, clientId, tokens }) =>
        ({ resource, renewed: await refresh(clientId, tokens.refresh_token, resource) })));
      for (const { resource, renewed: token } of renewed) {
        expect(token.expires_in, resource).toBe(expected(resource));
        expect(lifetimeOf(token.access_token), resource).toBe(expected(resource));
      }
    });
  });

  describe('the long lifetime needs the MCP scope', () => {
    test('a request that names an MCP resource without tinycloud:mcp consent is refused, so no long token exists for it', async () => {
      for (const resource of MCP_RESOURCES) {
        const { clientId, code } = await authorizeCode('openid email', undefined);
        const response = await exchange(clientId, code, resource);
        expect(response.status, resource).toBe(400);
        expect(await response.json()).not.toHaveProperty('access_token');
      }
      // The same client without the resource is unaffected.
      const { tokens } = await issue('openid email', undefined);
      expect(tokens.expires_in).toBe(FIVE_MINUTES);
    });
  });

  describe('/oauth2/userinfo for an MCP token', () => {
    const userinfo = (token: string) => call('/oauth2/userinfo', { headers: { authorization: `Bearer ${token}` } });

    test('answers while the connection stands, and stops the moment the owner revokes, disconnects or signs out', async () => {
      const revoked = await issue('openid email offline_access tinycloud:mcp', MCP_RESOURCES[0]);
      expect((await userinfo(revoked.tokens.access_token)).status).toBe(200);
      const revoke = await call('/oauth2/revoke', {
        method: 'POST', headers: form,
        body: new URLSearchParams({ client_id: revoked.clientId, token: revoked.tokens.access_token, token_type_hint: 'access_token' }),
      });
      expect(revoke.status).toBe(200);
      expect((await userinfo(revoked.tokens.access_token)).status).toBe(401);

      const disconnected = await issue('openid email offline_access tinycloud:mcp', MCP_RESOURCES[1]);
      expect((await userinfo(disconnected.tokens.access_token)).status).toBe(200);
      await prisma.oauthConsent.deleteMany({ where: { clientId: disconnected.clientId } });
      expect((await userinfo(disconnected.tokens.access_token)).status).toBe(401);
    });

    test('a withdrawn token is refused however the Authorization header is written, including with no Bearer scheme', async () => {
      // The provider takes the whole header as the token when it has no "Bearer " prefix, so the guard must too.
      // The provider's JWS decoder also accepts `=` padding and skips spaces and tabs inside the signature, which does not
      // change what the signature covers, so those spellings of the same token must be refused too.
      const forms = (token: string) => [
        `Bearer ${token}`, `bearer ${token}`, `Bearer  ${token}`, token,
        `Bearer ${token}==`, `${token}==`, `Bearer ${token} ==`,
        `Bearer ${token.slice(0, -4)} ${token.slice(-4)}`, `Bearer ${token.slice(0, -4)}\t${token.slice(-4)}`,
      ];
      const revoked = await issue('openid email offline_access tinycloud:mcp', MCP_RESOURCES[0]);
      // Before it is withdrawn the provider answers the two forms it understands.
      for (const header of [`Bearer ${revoked.tokens.access_token}`, revoked.tokens.access_token]) {
        expect((await call('/oauth2/userinfo', { headers: { authorization: header } })).status, header.slice(0, 12)).toBe(200);
      }
      const revoke = await call('/oauth2/revoke', {
        method: 'POST', headers: form,
        body: new URLSearchParams({ client_id: revoked.clientId, token: revoked.tokens.access_token, token_type_hint: 'access_token' }),
      });
      expect(revoke.status).toBe(200);
      for (const header of forms(revoked.tokens.access_token)) {
        expect((await call('/oauth2/userinfo', { headers: { authorization: header } })).status, header.slice(0, 12)).toBe(401);
      }

      const disconnected = await issue('openid email offline_access tinycloud:mcp', MCP_RESOURCES[1]);
      await prisma.oauthConsent.deleteMany({ where: { clientId: disconnected.clientId } });
      for (const header of forms(disconnected.tokens.access_token)) {
        expect((await call('/oauth2/userinfo', { headers: { authorization: header } })).status, header.slice(0, 12)).toBe(401);
      }
    });

    test('a token for another audience is answered by the provider as before', async () => {
      const { tokens } = await issue('openid email', OPENKEY_AUDIENCE);
      const response = await userinfo(tokens.access_token);
      expect(response.status).toBe(200);
      await prisma.oauthConsent.deleteMany();
      expect((await userinfo(tokens.access_token)).status).toBe(200);
    });
  });

  describe('revoking a long-lived MCP token', () => {
    test('the revoke is recorded until the token\'s own, later, expiry', async () => {
      const { clientId, tokens } = await issue('openid email offline_access tinycloud:mcp', MCP_RESOURCES[0]);
      const response = await call('/oauth2/revoke', {
        method: 'POST', headers: form,
        body: new URLSearchParams({ client_id: clientId, token: tokens.access_token, token_type_hint: 'access_token' }),
      });
      expect(response.status, await response.clone().text()).toBe(200);
      const rows = await prisma.revokedAccessToken.findMany({ where: { clientId } });
      expect(rows.length).toBe(1);
      expect(rows[0]!.expiresAt.getTime() / 1000).toBe(decodeJwt(tokens.access_token).exp!);
    });
  });
}
