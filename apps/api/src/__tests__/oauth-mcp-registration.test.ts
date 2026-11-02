import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { serializeSignedCookie } from 'better-call';
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';
import type { PrismaClient } from '@openkey/db';

// API unit tests replace modules process-wide. Exercise the real provider and
// tracked database migrations in a separate process, as the native OAuth tests do.
const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_MCP_OAUTH_TEST_CHILD !== '1') {
  test('MCP OAuth registration and consent through the real provider', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_MCP_OAUTH_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'mcp-registration-isolated-test-secret',
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
  const resource = 'https://mcp.tinycloud.xyz/mcp';
  const callback = 'https://chatgpt.com/connector_platform_oauth_redirect';
  const verifier = 'mcp-registration-pkce-verifier-012345678901234567890';
  const requestedScope = 'openid email offline_access tinycloud:mcp';
  const ownerAddress = '0x31d40B62C395B9418C4198363619B11c65cD406F';
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookie: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-mcp-registration-'));
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
    await prisma.user.create({ data: {
      id: 'mcp-owner', email: 'mcp-owner@example.test', name: 'MCP Owner', emailVerified: true,
    } });
    await prisma.ethereumKey.create({ data: {
      id: 'mcp-owner-key', userId: 'mcp-owner', address: ownerAddress, publicKey: '0x1', keyType: 'EXTERNAL',
    } });
    const sessionToken = randomUUID();
    await prisma.session.create({ data: {
      id: 'mcp-owner-session', userId: 'mcp-owner', token: sessionToken,
      expiresAt: new Date(Date.now() + 3_600_000),
    } });
    const context = await authModule.auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  function call(path: string, init: RequestInit = {}, authenticated = false) {
    return app.fetch(new Request(`${issuer}${path}`, {
      ...init,
      headers: { ...(authenticated ? { cookie } : {}), ...init.headers },
    }));
  }

  async function register(scope?: string) {
    const response = await call('/oauth2/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'MCP scope regression', redirect_uris: [callback],
        token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'], ...(scope === undefined ? {} : { scope }),
      }),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    return (await response.json() as { client_id: string }).client_id;
  }

  async function authorize(clientId: string, scope: string, authenticated = false, targetResource = resource) {
    const query = new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: callback, scope, resource: targetResource,
      state: 'mcp-state', code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256',
    });
    const response = await call(`/oauth2/authorize?${query}`, {}, authenticated);
    expect(response.status, await response.clone().text()).toBe(302);
    return new URL(response.headers.get('location')!, issuer);
  }

  describe('MCP dynamic client scope boundaries', () => {
    test.each([resource, 'https://mcp.tinycloud.xyz/chatgpt/mcp'])('%s requires login and owner consent before issuing resource-bound MCP tokens', async (targetResource) => {
      const clientId = await register();
      const login = await authorize(clientId, requestedScope, false, targetResource);
      expect(login.searchParams.get('error')).toBeNull();
      expect(login.origin + login.pathname).toBe('https://openkey.test/auth/login');
      const consent = await authorize(clientId, requestedScope, true, targetResource);
      expect(consent.origin + consent.pathname).toBe('https://openkey.test/oauth/consent');
      expect(await prisma.oauthConsent.count({ where: { clientId } })).toBe(0);
      expect(await prisma.oauthAccessToken.count({ where: { clientId } })).toBe(0);

      const approve = await call('/oauth2/consent', {
        method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://openkey.test' },
        body: JSON.stringify({ accept: true, oauth_query: consent.searchParams.toString() }),
      }, true);
      expect(approve.status, await approve.clone().text()).toBe(200);
      const redirect = new URL((await approve.json() as { url: string }).url);
      expect(redirect.origin + redirect.pathname).toBe(callback);
      expect(redirect.searchParams.get('state')).toBe('mcp-state');
      expect(redirect.searchParams.get('error')).toBeNull();
      const code = redirect.searchParams.get('code');
      expect(code).toBeTruthy();
      const exchanged = await call('/oauth2/token', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: clientId, grant_type: 'authorization_code', code: code!,
          redirect_uri: callback, code_verifier: verifier, resource: targetResource,
        }),
      });
      expect(exchanged.status, await exchanged.clone().text()).toBe(200);
      const tokens = await exchanged.json() as { access_token: string; refresh_token: string };
      const jwks = await (await call('/jwks')).json() as JSONWebKeySet;
      const { payload } = await jwtVerify(tokens.access_token, createLocalJWKSet(jwks), { issuer, audience: targetResource });
      const otherResource = targetResource === resource ? 'https://mcp.tinycloud.xyz/chatgpt/mcp' : resource;
      await expect(jwtVerify(tokens.access_token, createLocalJWKSet(jwks), { issuer, audience: otherResource })).rejects.toThrow();
      expect(payload.sub).toBe('mcp-owner');
      expect(payload.scope).toBe(requestedScope);
      expect(payload['https://tinycloud.xyz/owner_dids']).toEqual([`did:pkh:eip155:1:${ownerAddress}`]);
      const refreshed = await call('/oauth2/token', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: clientId, grant_type: 'refresh_token', refresh_token: tokens.refresh_token, resource: targetResource }),
      });
      expect(refreshed.status, await refreshed.clone().text()).toBe(200);
      const renewed = await refreshed.json() as { access_token: string };
      const { payload: renewedClaims } = await jwtVerify(renewed.access_token, createLocalJWKSet(jwks), { issuer, audience: targetResource });
      expect(renewedClaims.scope).toBe(requestedScope);
      expect(renewedClaims['https://tinycloud.xyz/owner_dids']).toEqual(payload['https://tinycloud.xyz/owner_dids']);
    });

    test('explicitly narrower registrations do not acquire MCP access', async () => {
      const clientId = await register('openid');
      const rejected = await authorize(clientId, requestedScope, true);
      expect(rejected.origin + rejected.pathname).toBe(callback);
      expect(rejected.searchParams.get('error')).toBe('invalid_scope');
      expect(await prisma.oauthConsent.count({ where: { clientId } })).toBe(0);
    });

    test('default registrations cannot request privileged TinyCloud signing scopes', async () => {
      const clientId = await register();
      for (const scope of ['tinycloud:session', 'tinycloud:manage-key', 'tinycloud:delegation']) {
        const rejected = await authorize(clientId, `openid ${scope}`, true);
        expect(rejected.searchParams.has('error')).toBe(true);
        expect(rejected.searchParams.get('code')).toBeNull();
      }
      expect(await prisma.oauthConsent.count({ where: { clientId } })).toBe(0);
      expect(await prisma.oauthAccessToken.count({ where: { clientId } })).toBe(0);
    });
  });
}
