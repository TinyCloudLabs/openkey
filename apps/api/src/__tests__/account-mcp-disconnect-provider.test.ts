import { afterAll, beforeAll, expect, test } from 'bun:test';
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
  test('disconnecting an MCP app ends its refresh and access tokens on the real provider', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_MCP_OAUTH_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'mcp-disconnect-isolated-test-secret',
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
  const verifier = 'mcp-disconnect-pkce-verifier-012345678901234567890123';
  const requestedScope = 'openid email offline_access tinycloud:mcp';
  const ownerAddress = '0x31d40B62C395B9418C4198363619B11c65cD406F';
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookie: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-mcp-disconnect-'));
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
    await prisma.user.create({ data: { id: 'mcp-owner', email: 'mcp-owner@example.test', name: 'MCP Owner', emailVerified: true } });
    await prisma.user.create({ data: { id: 'bystander', email: 'bystander@example.test', name: 'Bystander', emailVerified: true } });
    await prisma.ethereumKey.create({ data: { id: 'mcp-owner-key', userId: 'mcp-owner', address: ownerAddress, publicKey: '0x1', keyType: 'EXTERNAL' } });
    const sessionToken = randomUUID();
    await prisma.session.create({ data: { id: 'mcp-owner-session', userId: 'mcp-owner', token: sessionToken, expiresAt: new Date(Date.now() + 3_600_000) } });
    const context = await authModule.auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  const call = (path: string, init: RequestInit = {}, authenticated = false) => app.fetch(new Request(`${issuer}${path}`, {
    ...init, headers: { ...(authenticated ? { cookie } : {}), ...init.headers },
  }));
  const account = (path: string, init: RequestInit = {}) => app.fetch(new Request(`https://api.openkey.test/api/account${path}`, {
    ...init, headers: { cookie, origin: 'https://openkey.test', 'content-type': 'application/json', ...init.headers },
  }));
  const refresh = (clientId: string, token: string, withResource: boolean) => call('/oauth2/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, grant_type: 'refresh_token', refresh_token: token, ...(withResource ? { resource } : {}) }),
  });
  const rows = async (userId: string, clientId: string) => ({
    consent: await prisma.oauthConsent.count({ where: { userId, clientId } }),
    refresh: await prisma.oauthRefreshToken.count({ where: { userId, clientId } }),
    access: await prisma.oauthAccessToken.count({ where: { userId, clientId } }),
  });

  async function connectMcpApp() {
    const registered = await call('/oauth2/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Disconnect regression', redirect_uris: [callback], token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
      }),
    });
    expect(registered.status, await registered.clone().text()).toBe(200);
    const clientId = (await registered.json() as { client_id: string }).client_id;
    const query = new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: callback, scope: requestedScope, resource,
      state: 'mcp-state', code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256',
    });
    const authorized = await call(`/oauth2/authorize?${query}`, {}, true);
    expect(authorized.status, await authorized.clone().text()).toBe(302);
    const consentUrl = new URL(authorized.headers.get('location')!, issuer);
    const approve = await call('/oauth2/consent', {
      method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://openkey.test' },
      body: JSON.stringify({ accept: true, oauth_query: consentUrl.searchParams.toString() }),
    }, true);
    expect(approve.status, await approve.clone().text()).toBe(200);
    const code = new URL((await approve.json() as { url: string }).url).searchParams.get('code');
    const exchanged = await call('/oauth2/token', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: clientId, grant_type: 'authorization_code', code: code!, redirect_uri: callback, code_verifier: verifier, resource }),
    });
    expect(exchanged.status, await exchanged.clone().text()).toBe(200);
    return { clientId, tokens: await exchanged.json() as { access_token: string; refresh_token: string } };
  }

  test('after Disconnect the refresh grant and a pre-disconnect opaque token stop working; other tokens stay', async () => {
    console.log = (...args: unknown[]) => { process.stderr.write(`${args.map(String).join(' ')}\n`); };
    const { clientId, tokens } = await connectMcpApp();

    // A second refresh without a resource yields an opaque access token and a rotated refresh token.
    const renewed = await refresh(clientId, tokens.refresh_token, false);
    expect(renewed.status, await renewed.clone().text()).toBe(200);
    const live = await renewed.json() as { access_token: string; refresh_token: string };
    const userinfo = (token: string) => call('/oauth2/userinfo', { headers: { authorization: `Bearer ${token}` } });
    expect((await userinfo(live.access_token)).status).toBe(200);

    // Rows that belong to other clients and users must survive.
    for (const [userId, other, n] of [['bystander', clientId, 'bystander'], ['mcp-owner', 'other-client', 'other-client']] as const) {
      await prisma.oauthRefreshToken.create({ data: { id: `rt-${n}`, token: `refresh-${n}`, clientId: other, userId, scopes: [], expiresAt: new Date(Date.now() + 3_600_000) } });
      await prisma.oauthAccessToken.create({ data: { id: `at-${n}`, token: `access-${n}`, clientId: other, userId, refreshId: `rt-${n}`, scopes: [], expiresAt: new Date(Date.now() + 3_600_000) } });
    }
    expect(await rows('mcp-owner', clientId)).toMatchObject({ consent: 1 });

    const listed = await (await account('/tinycloud-apps')).json() as { mcpApps: { consentId: string; clientId: string }[] };
    const consentId = listed.mcpApps.find((entry) => entry.clientId === clientId)!.consentId;
    const disconnected = await account(`/tinycloud-apps/mcp/${consentId}`, { method: 'DELETE', body: JSON.stringify({ confirmation: 'DISCONNECT' }) });
    expect(disconnected.status, await disconnected.clone().text()).toBe(200);

    expect(await rows('mcp-owner', clientId)).toEqual({ consent: 0, refresh: 0, access: 0 });
    for (const withResource of [false, true]) {
      const denied = await refresh(clientId, live.refresh_token, withResource);
      expect(denied.status).toBe(400);
      expect((await denied.json() as { error: string }).error).toBe('invalid_grant');
    }
    // The provider answers 400 invalid_request ("Invalid access token") for a token whose row is gone.
    const gone = await userinfo(live.access_token);
    expect(gone.status).toBe(400);
    expect(await gone.json()).toEqual({ error: 'invalid_request', error_description: 'Invalid access token' });

    expect(await rows('bystander', clientId)).toEqual({ consent: 0, refresh: 1, access: 1 });
    expect(await rows('mcp-owner', 'other-client')).toEqual({ consent: 0, refresh: 1, access: 1 });
  }, 90_000);
}
