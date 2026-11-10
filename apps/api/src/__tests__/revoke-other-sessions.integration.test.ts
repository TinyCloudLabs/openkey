import { afterAll, beforeAll, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_REVOKE_TEST_CHILD !== '1') {
  test('revoke-other-sessions retains only the current session at 10, 53, and 120 sessions', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_REVOKE_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'revoke-other-sessions-isolated-test-secret',
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
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookieName: string;
  let secret: string;

  beforeAll(async () => {
    process.env.WEBAUTHN_ORIGIN = 'https://openkey.test';
    directory = await mkdtemp(join(tmpdir(), 'openkey-revoke-sessions-'));
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
    cookieName = context.authCookies.sessionToken.name;
    secret = context.secret;
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  test('revoke-other-sessions retains only the current session at 10, 53, and 120 sessions', async () => {
    const remaining: number[] = [];
    for (const count of [10, 53, 120]) {
      const userId = `revoke-user-${count}`;
      await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
      const tokens = Array.from({ length: count }, () => randomUUID());
      await prisma.session.createMany({
        data: tokens.map((token) => ({ id: randomUUID(), userId, token, expiresAt: new Date(Date.now() + 7 * 86_400_000) })),
      });
      const otherUserId = `revoke-other-user-${count}`;
      await prisma.user.create({ data: { id: otherUserId, email: `${otherUserId}@example.test`, name: otherUserId, emailVerified: true } });
      await prisma.session.create({ data: {
        id: randomUUID(), userId: otherUserId, token: randomUUID(), expiresAt: new Date(Date.now() + 7 * 86_400_000),
      } });
      const cookie = (await serializeSignedCookie(cookieName, tokens[0]!, secret)).split(';')[0]!;
      const call = (path: string, method: 'GET' | 'POST') => app.fetch(new Request(`https://api.openkey.test/api/auth${path}`, {
        method, headers: { cookie, origin: 'https://openkey.test' },
      }));
      if (count === 10) {
        const consoleRefused = await app.fetch(new Request(`https://api.openkey.test/api/auth/revoke-other-sessions`, {
          method: 'POST', headers: { cookie, origin: 'https://console.openkey.so' },
        }));
        expect(consoleRefused.status).toBe(403);
        const consoleSession = await app.fetch(new Request(`https://api.openkey.test/api/auth/get-session`, {
          headers: { cookie, origin: 'https://console.openkey.so' },
        }));
        expect(consoleSession.status).toBe(200);
      }

      const revoked = await call('/revoke-other-sessions', 'POST');
      expect(revoked.status).toBe(200);
      expect(await revoked.json()).toEqual({ status: true });
      const listed = await call('/list-sessions', 'GET');
      expect(listed.status).toBe(200);
      const sessions = await listed.json() as Array<unknown>;
      expect(await prisma.session.count({ where: { userId, token: tokens[0] } })).toBe(1);
      expect(await prisma.session.count({ where: { userId: otherUserId } })).toBe(1);
      remaining.push(sessions.length);
      console.log(`N=${count} remaining=${sessions.length}`);
    }
    expect(remaining).toEqual([1, 1, 1]);

    const userId = 'revoke-user-expired-prefix';
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    const expiredAt = new Date(Date.now() - 86_400_000);
    const oldCreatedAt = new Date(Date.now() - 30 * 86_400_000);
    await prisma.session.createMany({
      data: Array.from({ length: 150 }, () => ({
        id: randomUUID(), userId, token: randomUUID(), createdAt: oldCreatedAt, expiresAt: expiredAt,
      })),
    });
    const activeTokens = Array.from({ length: 53 }, () => randomUUID());
    await prisma.session.createMany({
      data: activeTokens.map((token) => ({
        id: randomUUID(), userId, token, expiresAt: new Date(Date.now() + 7 * 86_400_000),
      })),
    });
    const cookie = (await serializeSignedCookie(cookieName, activeTokens[0]!, secret)).split(';')[0]!;
    const call = (path: string, method: 'GET' | 'POST') => app.fetch(new Request(`https://api.openkey.test/api/auth${path}`, {
      method, headers: { cookie, origin: 'https://openkey.test' },
    }));
    const revoked = await call('/revoke-other-sessions', 'POST');
    expect(revoked.status).toBe(200);
    expect(await revoked.json()).toEqual({ status: true });
    const listed = await call('/list-sessions', 'GET');
    expect(listed.status).toBe(200);
    const sessions = await listed.json() as Array<unknown>;
    console.log(`N=150 expired + 53 active remaining=${sessions.length}`);
    expect(sessions).toHaveLength(1);
  });
  test('passkey registration proxy rejects console-origin requests before forwarding', async () => {
    const userId = 'passkey-origin-user';
    const token = randomUUID();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    await prisma.session.create({
      data: { id: randomUUID(), userId, token, expiresAt: new Date(Date.now() + 7 * 86_400_000) },
    });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    const proxyCall = (path: string, origin: string, body: unknown = {}) => app.fetch(new Request(`https://api.openkey.test/api/passkey/${path}`, {
      method: 'POST',
      headers: { cookie, origin, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }));

    const consoleOptions = await proxyCall('generate-register-options', 'https://console.openkey.so', { name: 'console passkey' });
    expect(consoleOptions.status).toBe(403);

    const accountOptions = await proxyCall('generate-register-options', 'http://localhost:5173', { name: 'account passkey' });
    expect(accountOptions.status).toBe(200);

    const consoleVerification = await proxyCall('verify-registration', 'https://console.openkey.so', {
      challengeToken: 'not-a-real-challenge',
      response: {},
    });
    expect(consoleVerification.status).toBe(403);
    expect(await prisma.passkey.count({ where: { userId } })).toBe(0);
  });
  test('sensitive token and OAuth client routes reject non-account origins before database changes', async () => {
    const userId = 'sensitive-auth-origin-user';
    const token = randomUUID();
    await prisma.user.create({
      data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true },
    });
    await prisma.session.create({
      data: { id: randomUUID(), userId, token, expiresAt: new Date(Date.now() + 7 * 86_400_000) },
    });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    const routes = [
      { method: 'POST', path: '/get-access-token', body: { providerId: 'google' } },
      { method: 'POST', path: '/oauth2/client/rotate-secret', body: { client_id: 'missing-client' } },
      {
        method: 'POST',
        path: '/oauth2/update-client',
        body: { client_id: 'missing-client', update: { client_name: 'No client' } },
      },
    ] as const;
    const snapshot = async () => ({
      users: await prisma.user.count({ where: { id: userId } }),
      sessions: await prisma.session.count({ where: { userId } }),
      accounts: await prisma.account.count({ where: { userId } }),
      clients: await prisma.oauthClient.count({ where: { userId } }),
      accessTokens: await prisma.oauthAccessToken.count({ where: { userId } }),
      refreshTokens: await prisma.oauthRefreshToken.count({ where: { userId } }),
    });
    const before = await snapshot();
    for (const route of routes) {
      const request = (headers: Record<string, string>) => app.fetch(new Request(
        `https://api.openkey.test/api/auth${route.path}`,
        {
          method: route.method,
          headers: { ...headers, ...(route.body ? { 'content-type': 'application/json' } : {}) },
          ...(route.body ? { body: JSON.stringify(route.body) } : {}),
        },
      ));
      for (const origin of ['https://console.openkey.so', 'https://staging.openkey.test', 'null']) {
        const response = await request({ cookie, origin });
        expect(response.status, `${route.path} from ${origin}`).toBe(403);
        expect(await snapshot()).toEqual(before);
      }
      const bearer = await request({ authorization: `Bearer ${token}` });
      expect(bearer.status, `${route.path} bearer without Origin`).toBe(403);
      expect(await snapshot()).toEqual(before);

      const account = await request({ cookie, origin: 'https://openkey.test' });
      expect(account.status, `${route.path} account cookie reaches endpoint`).not.toBe(403);
    }
  });
  test('organization OAuth clients are managed through the tenant console, not session client endpoints', async () => {
    const removedUserId = 'org-app-creator';
    const adminUserId = 'org-app-admin';
    const removedToken = randomUUID();
    const adminToken = randomUUID();
    await prisma.user.createMany({ data: [
      { id: removedUserId, email: `${removedUserId}@example.test`, name: removedUserId, emailVerified: true },
      { id: adminUserId, email: `${adminUserId}@example.test`, name: adminUserId, emailVerified: true },
    ] });
    await prisma.session.createMany({ data: [
      { id: randomUUID(), userId: removedUserId, token: removedToken, expiresAt: new Date(Date.now() + 7 * 86_400_000) },
      { id: randomUUID(), userId: adminUserId, token: adminToken, expiresAt: new Date(Date.now() + 7 * 86_400_000) },
    ] });
    await prisma.organization.create({ data: { id: 'org-app-authz', name: 'App authorization' } });
    await prisma.planEntitlements.create({ data: {
      id: 'org-app-entitlements', organizationId: 'org-app-authz', maxApps: 5, maxOrganizationMembers: 5,
      requestsPerMinute: 60, auditRetentionDays: 7,
    } });
    const removedMembership = await prisma.organizationMembership.create({
      data: { id: 'org-app-creator-membership', organizationId: 'org-app-authz', userId: removedUserId, role: 'ADMIN' },
    });
    await prisma.organizationMembership.create({
      data: { id: 'org-app-admin-membership', organizationId: 'org-app-authz', userId: adminUserId, role: 'ADMIN' },
    });
    const cookie = async (token: string) => (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    const creatorCookie = await cookie(removedToken);
    const adminCookie = await cookie(adminToken);
    const created = await app.fetch(new Request('https://api.openkey.test/api/console/organizations/org-app-authz/apps', {
      method: 'POST', headers: { cookie: creatorCookie, origin: 'https://console.openkey.so', 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Organization app', redirectUris: ['https://example.test/callback'] }),
    }));
    expect(created.status, await created.clone().text()).toBe(201);
    const newClient = (await created.json() as { client: { id: string; clientId: string } }).client;
    expect(await prisma.oauthClient.findUnique({ where: { id: newClient.id }, select: { userId: true } })).toEqual({ userId: null });
    const client = await prisma.oauthClient.create({ data: {
      id: 'legacy-org-app', clientId: 'ok_legacy_org_app', clientSecret: 'already-hashed-secret',
      name: 'Legacy organization app', redirectUris: ['https://example.test/legacy'],
      scopes: ['openid'], contacts: [], organizationId: 'org-app-authz', userId: removedUserId,
      tokenEndpointAuthMethod: 'client_secret_basic', public: false,
    } });
    const beforeRemoval = await prisma.oauthClient.findUnique({ where: { id: client.id } });
    for (const [path, body] of [
      ['/oauth2/update-client', { client_id: client.clientId, update: { client_name: 'Changed' } }],
      ['/oauth2/delete-client', { client_id: client.clientId }],
      ['/oauth2/client/rotate-secret', { client_id: client.clientId }],
    ] as const) {
      const refused = await app.fetch(new Request(`https://api.openkey.test/api/auth${path}`, {
        method: 'POST', headers: { cookie: creatorCookie, origin: 'https://openkey.test', 'content-type': 'application/json' },
        body: JSON.stringify(body),
      }));
      expect(refused.status, `${path} for creator admin`).toBe(401);
      expect(await prisma.oauthClient.findUnique({ where: { id: client.id } })).toEqual(beforeRemoval);
    }
    await prisma.organizationMembership.update({ where: { id: removedMembership.id }, data: { status: 'REVOKED', revokedAt: new Date(), validUntil: new Date() } });

    const call = (path: string, method: string, token: string, body?: unknown) => app.fetch(new Request(`https://api.openkey.test/api/auth${path}`, {
      method,
      headers: { cookie: token === removedToken ? creatorCookie : adminCookie, origin: 'https://openkey.test', ...(body ? { 'content-type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    }));
    const before = await prisma.oauthClient.findUnique({ where: { id: client.id } });
    for (const [path, body] of [
      ['/oauth2/update-client', { client_id: client.clientId, update: { client_name: 'Changed' } }],
      ['/oauth2/delete-client', { client_id: client.clientId }],
      ['/oauth2/client/rotate-secret', { client_id: client.clientId }],
    ] as const) {
      expect((await call(path, 'POST', removedToken, body)).status).toBe(401);
      expect((await call(path, 'POST', adminToken, body)).status).toBe(401);
      const bearer = await app.fetch(new Request(`https://api.openkey.test/api/auth${path}`, {
        method: 'POST', headers: { authorization: `Bearer ${removedToken}`, origin: 'https://openkey.test', 'content-type': 'application/json' },
        body: JSON.stringify(body),
      }));
      expect(bearer.status, `${path} bearer`).toBe(401);
      expect(await prisma.oauthClient.findUnique({ where: { id: client.id } })).toEqual(before);
    }
    const listed = await call('/oauth2/get-clients', 'GET', removedToken);
    expect(listed.status).toBe(200);
    expect((await listed.json() as Array<{ client_id: string }>).some(({ client_id }) => client_id === client.clientId)).toBe(false);
    expect((await call(`/oauth2/get-client?client_id=${client.clientId}`, 'GET', removedToken)).status).toBe(401);
    const updated = await app.fetch(new Request(`https://api.openkey.test/api/console/organizations/org-app-authz/apps/${client.id}`, {
      method: 'PATCH', headers: { cookie: adminCookie, origin: 'https://console.openkey.so', 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Admin managed' }),
    }));
    expect(updated.status, await updated.clone().text()).toBe(200);
    const deleted = await app.fetch(new Request(`https://api.openkey.test/api/console/organizations/org-app-authz/apps/${client.id}`, {
      method: 'DELETE', headers: { cookie: adminCookie, origin: 'https://console.openkey.so' },
    }));
    expect(deleted.status).toBe(200);
    const personalCreated = await call('/oauth2/create-client', 'POST', removedToken, {
      redirect_uris: ['https://example.test/personal'], client_name: 'Personal client',
    });
    expect(personalCreated.status, await personalCreated.clone().text()).toBe(200);
    const personalClient = await personalCreated.json() as { client_id: string };
    expect((await call(`/oauth2/get-client?client_id=${personalClient.client_id}`, 'GET', removedToken)).status).toBe(200);
    expect((await call('/oauth2/update-client', 'POST', removedToken, {
      client_id: personalClient.client_id, update: { client_name: 'Personal client updated' },
    })).status).toBe(200);
    expect((await call('/oauth2/client/rotate-secret', 'POST', removedToken, { client_id: personalClient.client_id })).status).toBe(200);
    expect((await call('/oauth2/update-client', 'POST', adminToken, {
      client_id: personalClient.client_id, update: { client_name: 'Not owner' },
    })).status).toBe(401);
    expect((await call('/oauth2/delete-client', 'POST', adminToken, { client_id: personalClient.client_id })).status).toBe(401);
    const personalClients = await call('/oauth2/get-clients', 'GET', removedToken);
    expect(personalClients.status).toBe(200);
    const listedClients = await personalClients.json() as Array<{ client_id: string; client_secret?: unknown }>;
    expect(listedClients.some(({ client_id }) => client_id === personalClient.client_id)).toBe(true);
    expect(listedClients.some(({ client_id }) => client_id === client.clientId)).toBe(false);
    expect(listedClients.find(({ client_id }) => client_id === personalClient.client_id)).not.toHaveProperty('client_secret');
    expect((await call('/oauth2/client/rotate-secret', 'POST', adminToken, { client_id: personalClient.client_id })).status).toBe(401);
    expect((await call('/oauth2/delete-client', 'POST', removedToken, { client_id: personalClient.client_id })).status).toBe(200);
  });
}
