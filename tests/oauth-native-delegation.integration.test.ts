import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { serializeSignedCookie } from 'better-call';
import { generateCodeChallenge } from 'better-auth/oauth2';
import type * as DatabaseModule from '@openkey/db';
import type * as AuthModule from '../apps/api/src/auth';

// TC-773 O2: fail-closed foundation for native TinyCloud delegation, proven
// through the API's public HTTP interface (the real Hono app in index.ts) on
// the tracked migration chain. Runs in a fresh process: other API tests
// replace @openkey/db and Better Auth globally.
const backend = process.env.TC773_NATIVE_TEST_CHILD;
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '..');

if (!backend) {
  for (const engine of ['pglite', 'postgres']) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(
      `TC-773 native delegation foundation (${engine})`,
      async () => {
        const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
          cwd: root,
          env: {
            ...process.env,
            TC773_NATIVE_TEST_CHILD: engine,
            NODE_ENV: 'test',
            TEE_MODE: 'development',
            BETTER_AUTH_URL: 'https://api.openkey.test',
            BETTER_AUTH_SECRET: 'tc773-isolated-regression-secret-not-for-production',
            WEBAUTHN_RP_ID: 'openkey.test',
            WEBAUTHN_ORIGIN: 'https://openkey.test',
            CORS_ORIGIN: 'https://openkey.test',
            ADMIN_API_KEY: 'tc773-admin-key',
            RESEND_API_KEY: '',
            GOOGLE_CLIENT_ID: '',
            GOOGLE_CLIENT_SECRET: '',
            TINYCLOUD_SQL_ISOLATED_HOSTS: '',
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
      },
      180_000,
    );
  }
} else {
  const directory = await mkdtemp(join(tmpdir(), 'openkey-tc773-'));
  const databaseName = `tc773_${randomUUID().replaceAll('-', '')}`;
  let admin: Client | undefined;
  let prisma: DatabaseModule.PrismaClient;
  let auth: typeof AuthModule.auth;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookie: string;

  const API = 'https://api.openkey.test';
  const ISSUER = `${API}/api/auth`;
  const WEB_ORIGIN = 'https://openkey.test';
  const NATIVE_REDIRECT = 'xyz.tinycloud.exo://openkey/callback';
  const ORDINARY_REDIRECT = 'https://ordinary.example/callback';
  const DELEGATION = 'tinycloud:delegation';
  const alice = 'tc773-alice';
  const bob = 'tc773-bob';
  const ceiling = {
    version: 1,
    appId: 'xyz.tinycloud.tinychat',
    tinycloudHost: 'https://tee.node.tinycloud.xyz',
    kv: {
      paths: ['xyz.tinycloud.tinychat/threads/', 'xyz.tinycloud.tinychat/connectors/'],
      actions: ['get', 'put', 'list', 'del', 'metadata'],
    },
    sql: null,
    maxDelegationTtlSeconds: 3600,
  };
  let nativeClient: string;
  let ordinaryClient: string;

  const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
  const basic = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

  function call(path: string, init: RequestInit = {}) {
    return app.fetch(new Request(`${API}${path}`, init));
  }

  function form(path: string, body: string, headers: Record<string, string> = {}) {
    return call(path, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body,
    });
  }

  function adminRequest(method: string, path: string, body?: unknown) {
    return call(`/api/admin/oauth${path}`, {
      method,
      headers: { authorization: 'Bearer tc773-admin-key', 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  }

  async function seedRefreshToken(id: string, raw: string, clientId: string, options: {
    userId?: string;
    scopes?: string[];
    revoked?: boolean;
  } = {}) {
    await prisma.oauthRefreshToken.create({ data: {
      id,
      token: hash(raw),
      clientId,
      userId: options.userId ?? alice,
      scopes: options.scopes ?? ['openid', 'offline_access', DELEGATION],
      revoked: options.revoked ? new Date() : null,
      expiresAt: new Date(Date.now() + 7 * 86_400_000),
    } });
  }

  async function seedGrant(id: string, clientId: string, options: {
    userId?: string;
    current?: string | null;
    previous?: string | null;
  } = {}) {
    await prisma.tinyCloudNativeGrant.create({ data: {
      id,
      userId: options.userId ?? alice,
      clientId,
      consentId: `consent-${clientId}`,
      consentGeneration: 0n,
      keyId: 'key',
      address: '0x31d40B62C395B9418C4198363619B11c65cD406F',
      sessionDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      sessionJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
      sessionJkt: 'jkt',
      spaceId: 'tinycloud:pkh:eip155:1:0x31d40B62C395B9418C4198363619B11c65cD406F:applications',
      approvedPermissions: [],
      ttlSeconds: 3600,
      tinycloudHost: 'https://tee.node.tinycloud.xyz',
      refreshTokenHash: options.current === null ? null : hash(options.current ?? `${id}-token`),
      previousRefreshTokenHash: options.previous ? hash(options.previous) : null,
      absoluteExpiresAt: new Date(Date.now() + 30 * 86_400_000),
    } });
  }

  async function tokenState() {
    const [refresh, access] = await Promise.all([
      prisma.oauthRefreshToken.findMany({ select: { id: true, revoked: true }, orderBy: { id: 'asc' } }),
      prisma.oauthAccessToken.findMany({ select: { id: true }, orderBy: { id: 'asc' } }),
    ]);
    return { refresh: refresh.map((row) => ({ id: row.id, revoked: row.revoked !== null })), access: access.map((row) => row.id) };
  }

  async function oauthError(response: Response) {
    return await response.json() as { error?: string; error_description?: string };
  }

  beforeAll(async () => {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    let connectionString: string;
    if (backend === 'postgres') {
      if (!postgresUrl) throw new Error('OPENKEY_TEST_POSTGRES_URL is required for PostgreSQL coverage');
      // Never migrate the supplied database; all data lives in a disposable one.
      admin = new Client({ connectionString: postgresUrl });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${databaseName}"`);
      const target = new URL(postgresUrl);
      target.pathname = `/${databaseName}`;
      connectionString = target.toString();
      const migrationConnection = new Client({ connectionString });
      await migrationConnection.connect();
      try {
        for (const migration of migrations) {
          await migrationConnection.query(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
        }
      } finally {
        await migrationConnection.end();
      }
    } else {
      const database = new PGlite(directory);
      try {
        for (const migration of migrations) {
          await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
        }
      } finally {
        await database.close();
      }
      connectionString = `pglite:${directory}`;
    }
    process.env.DATABASE_URL = connectionString;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    // Route singletons capture DATABASE_URL on import, so the app loads only
    // after the disposable database exists.
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
    ({ auth } = await import('../apps/api/src/auth'));
    app = (await import('../apps/api/src/index')).default;

    await prisma.user.createMany({ data: [
      { id: alice, email: 'alice@example.test', name: 'Alice', emailVerified: true },
      { id: bob, email: 'bob@example.test', name: 'Bob', emailVerified: true },
    ] });
    const sessionToken = randomUUID();
    await prisma.session.create({ data: {
      id: 'tc773-session', token: sessionToken, userId: alice, expiresAt: new Date(Date.now() + 3_600_000),
    } });
    const context = await auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;

    const native = await adminRequest('POST', '/clients', {
      name: 'Exo native', type: 'native', redirectUris: [NATIVE_REDIRECT], tinycloudNativeDelegation: ceiling,
    });
    expect(native.status).toBe(201);
    nativeClient = (await native.json() as { client: { clientId: string } }).client.clientId;
    const ordinary = await adminRequest('POST', '/clients', {
      name: 'Ordinary SPA', type: 'spa', redirectUris: [ORDINARY_REDIRECT],
    });
    expect(ordinary.status).toBe(201);
    ordinaryClient = (await ordinary.json() as { client: { clientId: string } }).client.clientId;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await admin.end();
    }
    await rm(directory, { recursive: true, force: true });
  });

  // TRUNCATE fires no row triggers, so resetting never touches generations.
  beforeEach(async () => {
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE "oauth_refresh_token", "oauth_access_token", "oauth_consent",
      "tinycloud_native_grant", "tinycloud_native_request", "tinycloud_native_consent_generation", "verification" CASCADE`);
    // Device A and device B: two live native sessions of the same user.
    await seedRefreshToken('native-a', 'native-device-a', nativeClient);
    await seedRefreshToken('native-b', 'native-device-b', nativeClient);
    await seedGrant('grant-a', nativeClient, { current: 'native-device-a', previous: 'native-device-a-rotated' });
    await seedGrant('grant-b', nativeClient, { current: 'native-device-b' });
    await seedRefreshToken('ordinary-live', 'ordinary-live', ordinaryClient, { scopes: ['openid', 'offline_access'] });
    await seedRefreshToken('ordinary-revoked', 'ordinary-revoked', ordinaryClient, {
      scopes: ['openid', 'offline_access'], revoked: true,
    });
    await prisma.oauthAccessToken.create({ data: {
      id: 'native-a-access', token: hash('native-a-access'), clientId: nativeClient, userId: alice,
      refreshId: 'native-a', scopes: ['openid', DELEGATION], expiresAt: new Date(Date.now() + 300_000),
    } });
  });

  const seededState = {
    refresh: [
      { id: 'native-a', revoked: false },
      { id: 'native-b', revoked: false },
      { id: 'ordinary-live', revoked: false },
      { id: 'ordinary-revoked', revoked: true },
    ],
    access: ['native-a-access'],
  };

  describe(`client enablement and scope isolation (${backend})`, () => {
    test('the admin route stores the canonical ceiling and adds the scope only with it', async () => {
      const stored = await prisma.oauthClient.findUniqueOrThrow({ where: { clientId: nativeClient } });
      expect(stored.scopes).toContain(DELEGATION);
      expect(stored.tinycloudNativeDelegation).toEqual({
        ...ceiling, grantLifetimeSeconds: 30 * 24 * 60 * 60,
      });
      const ordinary = await prisma.oauthClient.findUniqueOrThrow({ where: { clientId: ordinaryClient } });
      expect(ordinary.scopes).not.toContain(DELEGATION);
      expect(ordinary.tinycloudNativeDelegation).toBeNull();
    });

    test('enablement is refused for non-native clients, scope-only requests and SQL on non-isolated hosts', async () => {
      const refused = [
        { name: 'SPA', type: 'spa', redirectUris: [ORDINARY_REDIRECT], tinycloudNativeDelegation: ceiling },
        { name: 'Scope only', type: 'native', redirectUris: [NATIVE_REDIRECT], scopes: ['openid', DELEGATION] },
        {
          name: 'SQL', type: 'native', redirectUris: [NATIVE_REDIRECT],
          tinycloudNativeDelegation: { ...ceiling, sql: { databases: ['xyz.tinycloud.tinychat/threads'], actions: ['read'] } },
        },
      ];
      for (const body of refused) {
        const response = await adminRequest('POST', '/clients', body);
        expect(response.status, body.name).toBe(400);
      }
      const added = await adminRequest('PATCH', `/clients/${ordinaryClient}`, { scopes: ['openid', DELEGATION] });
      expect(added.status).toBe(400);
      const plain = await adminRequest('POST', '/clients', { name: 'Plain native', type: 'native', redirectUris: [NATIVE_REDIRECT] });
      const plainClient = (await plain.json() as { client: { clientId: string } }).client.clientId;
      const onDisabled = await adminRequest('PATCH', `/clients/${plainClient}`, { disabled: true, tinycloudNativeDelegation: ceiling });
      expect(onDisabled.status).toBe(400);
      await prisma.oauthClient.delete({ where: { clientId: plainClient } });
      expect(await prisma.oauthClient.count({ where: { scopes: { has: DELEGATION } } })).toBe(1);

      process.env.TINYCLOUD_SQL_ISOLATED_HOSTS = 'https://tee.node.tinycloud.xyz';
      try {
        const sql = await adminRequest('POST', '/clients', refused[2]);
        expect(sql.status).toBe(201);
        const clientId = (await sql.json() as { client: { clientId: string } }).client.clientId;
        const disabled = await adminRequest('PATCH', `/clients/${clientId}`, { tinycloudNativeDelegation: null });
        expect(disabled.status).toBe(200);
        const row = await prisma.oauthClient.findUniqueOrThrow({ where: { clientId } });
        expect(row.scopes).not.toContain(DELEGATION);
        expect(row.tinycloudNativeDelegation).toBeNull();
        await prisma.oauthClient.delete({ where: { clientId } });
      } finally {
        process.env.TINYCLOUD_SQL_ISOLATED_HOSTS = '';
      }
    });

    test('dynamic registration cannot request the delegation scope', async () => {
      const register = (scope: string) => call('/api/auth/oauth2/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Dynamic', redirect_uris: [ORDINARY_REDIRECT], token_endpoint_auth_method: 'none',
          type: 'user-agent-based', scope,
        }),
      });
      for (const scope of [`openid ${DELEGATION}`, 'openid tinycloud:manage-key']) {
        const refused = await register(scope);
        expect(refused.status, scope).toBe(400);
        expect((await oauthError(refused)).error).toBe('invalid_scope');
      }
      expect((await register('openid')).status).toBe(200);
      expect(await prisma.oauthClient.count({ where: { scopes: { has: DELEGATION } } })).toBe(1);
    });

    test('a signed-in user cannot add or remove admin-managed scopes through create-client or update-client', async () => {
      const clientRoute = (path: string, body: unknown) => call(`/api/auth/oauth2/${path}`, {
        method: 'POST',
        headers: { cookie, origin: WEB_ORIGIN, 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      const adminManaged = () => prisma.oauthClient.count({
        where: { OR: [{ scopes: { has: DELEGATION } }, { scopes: { has: 'tinycloud:manage-key' } }] },
      });
      const before = await adminManaged();
      const created = (scope: string, extra: Record<string, unknown> = {}) => clientRoute('create-client', {
        client_name: 'User client', redirect_uris: [ORDINARY_REDIRECT], token_endpoint_auth_method: 'none',
        type: 'user-agent-based', scope, ...extra,
      });
      for (const [scope, extra] of [
        [`openid ${DELEGATION}`, {}],
        ['openid tinycloud:manage-key', {}],
        ['openid tinycloud:manage-key', { token_endpoint_auth_method: 'client_secret_basic', type: 'web' }],
      ] as const) {
        const response = await created(scope, extra);
        expect(response.status, scope).toBe(400);
        expect((await oauthError(response)).error).toBe('invalid_scope');
      }
      expect(await adminManaged()).toBe(before);

      // A user's own ordinary client: creation works, and so do ordinary scope
      // updates, but neither admin-managed scope can be added.
      const own = await created('openid email');
      expect(own.status).toBe(200);
      const ownClient = (await own.json() as { client_id: string }).client_id;
      for (const scope of [`openid ${DELEGATION}`, 'openid tinycloud:manage-key']) {
        const response = await clientRoute('update-client', { client_id: ownClient, update: { scope } });
        expect(response.status, scope).toBe(400);
        expect((await oauthError(response)).error).toBe('invalid_scope');
      }
      expect((await clientRoute('update-client', { client_id: ownClient, update: { scope: 'openid' } })).status).toBe(200);
      expect((await prisma.oauthClient.findUniqueOrThrow({ where: { clientId: ownClient } })).scopes).toEqual(['openid']);

      // A delegation-enabled client the user owns: its scopes can't be
      // changed, so the scope can't be removed apart from its ceiling.
      const enabled = await adminRequest('POST', '/clients', {
        name: 'User-owned native', type: 'native', redirectUris: [NATIVE_REDIRECT], tinycloudNativeDelegation: ceiling,
      });
      const enabledClient = (await enabled.json() as { client: { clientId: string } }).client.clientId;
      await prisma.oauthClient.update({ where: { clientId: enabledClient }, data: { userId: alice } });
      const scopes = (await prisma.oauthClient.findUniqueOrThrow({ where: { clientId: enabledClient } })).scopes;
      const removed = await clientRoute('update-client', { client_id: enabledClient, update: { scope: 'openid offline_access' } });
      expect(removed.status).toBe(400);
      expect((await oauthError(removed)).error).toBe('invalid_scope');
      expect((await prisma.oauthClient.findUniqueOrThrow({ where: { clientId: enabledClient } })).scopes).toEqual(scopes);
      // Other fields still update through the provider.
      expect((await clientRoute('update-client', { client_id: enabledClient, update: { client_name: 'Renamed' } })).status).toBe(200);
      await prisma.oauthClient.deleteMany({ where: { clientId: { in: [ownClient, enabledClient] } } });
      expect(await adminManaged()).toBe(before);
    });

    test('client routes: non-JSON bodies get 415, and JSON variants cannot smuggle an admin-managed scope', async () => {
      const send = (path: string, contentType: string | null, body: BodyInit) => call(`/api/auth/oauth2/${path}`, {
        method: 'POST',
        headers: { cookie, origin: WEB_ORIGIN, ...(contentType ? { 'content-type': contentType } : {}) },
        body,
      });
      const createFields = `"client_name":"Format","redirect_uris":["${ORDINARY_REDIRECT}"],"token_endpoint_auth_method":"none","type":"user-agent-based"`;
      const before = await prisma.oauthClient.count();
      const multipart = new FormData();
      multipart.append('client_name', 'Format');
      multipart.append('redirect_uris', ORDINARY_REDIRECT);
      multipart.append('scope', `openid ${DELEGATION}`);
      for (const [label, response] of [
        ['form', await send('create-client', 'application/x-www-form-urlencoded',
          `client_name=Format&redirect_uris=${encodeURIComponent(ORDINARY_REDIRECT)}&scope=${encodeURIComponent(`openid ${DELEGATION}`)}`)],
        ['multipart', await send('create-client', null, multipart)],
        ['text', await send('create-client', 'text/plain', `{${createFields},"scope":"openid ${DELEGATION}"}`)],
        ['update form', await send('update-client', 'application/x-www-form-urlencoded', `client_id=x&update=${encodeURIComponent(`{"scope":"${DELEGATION}"}`)}`)],
      ] as const) {
        expect(response.status, label).toBe(415);
      }
      for (const [label, response] of [
        ['charset json', await send('create-client', 'application/json; charset=utf-8', `{${createFields},"scope":"openid ${DELEGATION}"}`)],
        ['vendor json', await send('create-client', 'application/vnd.api+json', `{${createFields},"scope":"openid tinycloud:manage-key"}`)],
        // JSON.parse keeps the last duplicate, for the guard and the provider alike.
        ['duplicate keys, admin scope last', await send('create-client', 'application/json', `{${createFields},"scope":"openid","scope":"openid ${DELEGATION}"}`)],
      ] as const) {
        expect(response.status, label).toBe(400);
        expect((await oauthError(response)).error, label).toBe('invalid_scope');
      }
      expect(await prisma.oauthClient.count()).toBe(before);
      const benign = await send('create-client', 'application/json', `{${createFields},"scope":"openid ${DELEGATION}","scope":"openid"}`);
      expect(benign.status).toBe(200);
      const benignClient = (await benign.json() as { client_id: string; scope: string });
      expect(benignClient.scope).toBe('openid');
      const smuggled = await send('update-client', 'application/json; charset=utf-8',
        `{"client_id":"${benignClient.client_id}","update":{"scope":"openid","scope":"openid ${DELEGATION}"}}`);
      expect(smuggled.status).toBe(400);
      expect((await prisma.oauthClient.findUniqueOrThrow({ where: { clientId: benignClient.client_id } })).scopes).toEqual(['openid']);
      await prisma.oauthClient.delete({ where: { clientId: benignClient.client_id } });
    });

    test('a direct authorize request for the delegation scope is refused for every client', async () => {
      const challenge = await generateCodeChallenge('tc773-verifier-0123456789012345678901234567890');
      for (const [clientId, redirectUri] of [[nativeClient, NATIVE_REDIRECT], [ordinaryClient, ORDINARY_REDIRECT]] as const) {
        const query = new URLSearchParams({
          response_type: 'code', client_id: clientId, redirect_uri: redirectUri, state: 'state',
          scope: `openid offline_access ${DELEGATION}`, code_challenge: challenge, code_challenge_method: 'S256',
        });
        const response = await call(`/api/auth/oauth2/authorize?${query}`, { headers: { cookie } });
        expect(response.status).toBe(400);
        expect((await oauthError(response)).error).toBe('invalid_scope');
      }
      expect(await prisma.verification.count()).toBe(0);
    });

    test('a delegation client may not omit scope; ordinary clients still default', async () => {
      const challenge = await generateCodeChallenge('tc773-verifier-0123456789012345678901234567890');
      const authorize = (clientId: string, redirectUri: string) => call(`/api/auth/oauth2/authorize?${new URLSearchParams({
        response_type: 'code', client_id: clientId, redirect_uri: redirectUri, state: 'state',
        code_challenge: challenge, code_challenge_method: 'S256',
      })}`, { headers: { cookie } });
      const native = await authorize(nativeClient, NATIVE_REDIRECT);
      expect(native.status).toBe(400);
      expect((await oauthError(native)).error).toBe('invalid_scope');
      const ordinary = await authorize(ordinaryClient, ORDINARY_REDIRECT);
      expect(ordinary.status).toBe(302);
      expect(new URL(ordinary.headers.get('location')!).pathname).toBe('/oauth/consent');
    });

    test('repeated authorize parameters are refused before the provider resolves them', async () => {
      const response = await call(
        `/api/auth/oauth2/authorize?response_type=code&client_id=${ordinaryClient}&scope=openid&scope=${encodeURIComponent(DELEGATION)}`,
        { headers: { cookie } },
      );
      expect(response.status).toBe(400);
      expect((await oauthError(response)).error).toBe('invalid_request');
    });

    test('a delegation-scoped code minted behind the interceptor still yields no token', async () => {
      await prisma.oauthConsent.create({ data: {
        id: 'consent-native', userId: alice, clientId: nativeClient, scopes: ['openid', 'offline_access', DELEGATION],
      } });
      const verifier = 'tc773-code-verifier-0123456789012345678901234567890';
      const query = new URLSearchParams({
        response_type: 'code', client_id: nativeClient, redirect_uri: NATIVE_REDIRECT, state: 'state',
        scope: `openid offline_access ${DELEGATION}`, code_challenge: await generateCodeChallenge(verifier),
        code_challenge_method: 'S256',
      });
      // The provider itself, bypassing the app's authorize guard.
      const authorized = await auth.handler(new Request(`${ISSUER}/oauth2/authorize?${query}`, { headers: { cookie } }));
      expect(authorized.status).toBe(302);
      const code = new URL(authorized.headers.get('location')!).searchParams.get('code');
      expect(code).toBeTruthy();

      const before = await tokenState();
      const exchange = await form('/api/auth/oauth2/token', new URLSearchParams({
        grant_type: 'authorization_code', code: code!, code_verifier: verifier,
        client_id: nativeClient, redirect_uri: NATIVE_REDIRECT,
      }).toString());
      expect(exchange.status).toBe(400);
      expect((await oauthError(exchange)).error).toBe('invalid_grant');
      expect(await tokenState()).toEqual(before);
    });
  });

  describe(`refresh_token interception (${backend})`, () => {
    const refresh = (fields: Record<string, string>, headers: Record<string, string> = {}) =>
      form('/api/auth/oauth2/token', new URLSearchParams({ grant_type: 'refresh_token', ...fields }).toString(), headers);

    test('refuses native live, revoked and rotated refresh tokens with "use the renew endpoint" and no side effects', async () => {
      await prisma.oauthRefreshToken.update({ where: { id: 'native-b' }, data: { revoked: new Date() } });
      const state = await tokenState();
      for (const token of ['native-device-a', 'native-device-b', 'native-device-a-rotated']) {
        const response = await refresh({ client_id: nativeClient, refresh_token: token });
        expect(response.status, token).toBe(400);
        expect(await oauthError(response), token).toEqual({ error: 'invalid_grant', error_description: 'use the renew endpoint' });
      }
      expect(await tokenState()).toEqual(state);
    });

    test('refuses a native token under another client_id and any token presented by a delegation client', async () => {
      const byOwner = await refresh({ client_id: ordinaryClient, refresh_token: 'native-device-a' });
      expect(byOwner.status).toBe(400);
      expect((await oauthError(byOwner)).error).toBe('invalid_grant');
      const byRequest = await refresh({ client_id: nativeClient, refresh_token: 'ordinary-revoked' });
      expect(byRequest.status).toBe(400);
      const unknown = await refresh({ client_id: nativeClient, refresh_token: 'never-issued' });
      expect(unknown.status).toBe(400);
      expect(await tokenState()).toEqual(seededState);
    });

    test('same client: the native client\'s own revoked ordinary token never reaches the provider refresh grant', async () => {
      await seedRefreshToken('native-client-legacy', 'native-client-legacy', nativeClient, {
        scopes: ['openid', 'offline_access'], revoked: true,
      });
      const state = await tokenState();
      const grants = await prisma.tinyCloudNativeGrant.findMany({ orderBy: { id: 'asc' } });
      const response = await refresh({ client_id: nativeClient, refresh_token: 'native-client-legacy' });
      expect(response.status).toBe(400);
      expect(await oauthError(response)).toEqual({ error: 'invalid_grant', error_description: 'use the renew endpoint' });
      const viaBasic = await refresh({ refresh_token: 'native-client-legacy' }, { authorization: basic(nativeClient, 'unused') });
      expect((await oauthError(viaBasic)).error).toBe('invalid_grant');
      // Still native-capable once delegation is disabled: its grants remain.
      expect((await adminRequest('PATCH', `/clients/${nativeClient}`, { tinycloudNativeDelegation: null })).status).toBe(200);
      try {
        const disabled = await refresh({ client_id: nativeClient, refresh_token: 'native-client-legacy', scope: 'openid' });
        expect(await oauthError(disabled)).toEqual({ error: 'invalid_grant', error_description: 'use the renew endpoint' });
      } finally {
        expect((await adminRequest('PATCH', `/clients/${nativeClient}`, { tinycloudNativeDelegation: ceiling })).status).toBe(200);
      }
      expect(await tokenState()).toEqual(state);
      expect(await prisma.tinyCloudNativeGrant.findMany({ orderBy: { id: 'asc' } })).toEqual(grants);

      // The provider alone: the client matches, so its revoked-token branch
      // deletes every refresh token of the user for the client.
      await auth.handler(new Request(`${ISSUER}/oauth2/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', client_id: nativeClient, refresh_token: 'native-client-legacy' }).toString(),
      }));
      expect((await tokenState()).refresh.map((row) => row.id)).toEqual(['ordinary-live', 'ordinary-revoked']);
    });

    test('native tokens stay native after an admin disables delegation for their client', async () => {
      // One token native by its row scope only, one by its grant hash only.
      await seedRefreshToken('native-scope-only', 'native-scope-only', nativeClient);
      await seedRefreshToken('native-grant-only', 'native-grant-only', nativeClient, { scopes: ['openid', 'offline_access'] });
      await seedGrant('grant-only', nativeClient, { current: 'native-grant-only' });
      const disabled = await adminRequest('PATCH', `/clients/${nativeClient}`, { tinycloudNativeDelegation: null });
      expect(disabled.status).toBe(200);
      try {
        const client = await prisma.oauthClient.findUniqueOrThrow({ where: { clientId: nativeClient } });
        expect(client.scopes).not.toContain(DELEGATION);
        expect(client.tinycloudNativeDelegation).toBeNull();
        const state = await tokenState();
        for (const token of ['native-device-a', 'native-device-a-rotated', 'native-scope-only', 'native-grant-only']) {
          const response = await refresh({ client_id: nativeClient, refresh_token: token, scope: 'openid offline_access' });
          expect(response.status, token).toBe(400);
          expect(await oauthError(response), token).toEqual({ error: 'invalid_grant', error_description: 'use the renew endpoint' });
        }
        expect(await tokenState()).toEqual(state);
      } finally {
        const restored = await adminRequest('PATCH', `/clients/${nativeClient}`, { tinycloudNativeDelegation: ceiling });
        expect(restored.status).toBe(200);
      }
    });

    test('the Basic header identifies the client ahead of the body', async () => {
      const viaBasic = await refresh(
        { client_id: ordinaryClient, refresh_token: 'ordinary-revoked' },
        { authorization: basic(nativeClient, 'unused') },
      );
      expect(viaBasic.status).toBe(400);
      expect((await oauthError(viaBasic)).error).toBe('invalid_grant');
      const malformed = await refresh(
        { client_id: ordinaryClient, refresh_token: 'ordinary-live' },
        { authorization: `Basic ${Buffer.from(`${nativeClient}:x`).toString('base64url')}-` },
      );
      expect(malformed.status).toBe(401);
      expect(await tokenState()).toEqual(seededState);
    });

    test('duplicate keys and provider-accepted non-form bodies are refused', async () => {
      const duplicate = await form('/api/auth/oauth2/token',
        `grant_type=refresh_token&client_id=${ordinaryClient}&refresh_token=ordinary-live&refresh_token=native-device-a`);
      expect(duplicate.status).toBe(400);
      expect((await oauthError(duplicate)).error).toBe('invalid_request');
      const jsonInForm = await call('/api/auth/oauth2/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded+json' },
        body: JSON.stringify({ grant_type: 'refresh_token', client_id: nativeClient, refresh_token: 'native-device-a' }),
      });
      expect(jsonInForm.status).toBe(400);
      const json = await call('/api/auth/oauth2/token', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ grant_type: 'refresh_token', client_id: nativeClient, refresh_token: 'native-device-a' }),
      });
      expect(json.status).toBe(415);
      expect(await tokenState()).toEqual(seededState);
    });

    test('an ordinary client still refreshes through the provider', async () => {
      const response = await refresh({ client_id: ordinaryClient, refresh_token: 'ordinary-live' });
      expect(response.status).toBe(200);
      const body = await response.json() as { refresh_token?: string; access_token?: string };
      expect(body.refresh_token).toBeTruthy();
      expect(body.access_token).toBeTruthy();
    });
  });

  describe(`provider revoke interception (${backend})`, () => {
    const revoke = (fields: Record<string, string>, headers: Record<string, string> = {}) =>
      form('/api/auth/oauth2/revoke', new URLSearchParams(fields).toString(), headers);
    const unsupported = {
      error: 'unsupported_token_type',
      error_description: 'revoke TinyCloud delegation sessions at /api/auth/oauth2/tinycloud/revoke',
    };
    const notIssued = { error: 'invalid_request', error_description: 'token was not issued to this client' };
    const hints = [undefined, 'refresh_token', 'access_token'];

    async function seedAccessToken(id: string, clientId: string, scopes: string[], refreshId: string | null) {
      await prisma.oauthAccessToken.create({ data: {
        id, token: hash(id), clientId, userId: alice, refreshId, scopes, expiresAt: new Date(Date.now() + 300_000),
      } });
    }

    // The provider alone, behind no interceptor.
    function providerRevoke(fields: Record<string, string>) {
      return auth.handler(new Request(`${ISSUER}/oauth2/revoke`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(fields).toString(),
      }));
    }

    test('A2: an ordinary client\'s revoked token sent with a native client_id leaves both devices intact', async () => {
      const response = await revoke({ client_id: nativeClient, token: 'ordinary-revoked', token_type_hint: 'refresh_token' });
      expect(response.status).toBe(400);
      expect(await oauthError(response)).toEqual(unsupported);
      const viaBasic = await revoke({ token: 'ordinary-revoked' }, { authorization: basic(nativeClient, 'unused') });
      expect(await oauthError(viaBasic)).toEqual(unsupported);
      expect(await tokenState()).toEqual(seededState);

      // The same request straight to the provider deletes every native
      // refresh token of the user: the side effect the interceptor prevents.
      await providerRevoke({ client_id: nativeClient, token: 'ordinary-revoked', token_type_hint: 'refresh_token' });
      expect((await tokenState()).refresh.map((row) => row.id)).toEqual(['ordinary-live', 'ordinary-revoked']);
    });

    test('A2 with a Bearer prefix: refused before any lookup, every native token intact', async () => {
      for (const hint of hints) {
        const response = await revoke({
          client_id: nativeClient, token: 'Bearer ordinary-revoked', ...(hint ? { token_type_hint: hint } : {}),
        });
        expect(response.status, String(hint)).toBe(400);
        expect(await oauthError(response)).toEqual({ error: 'invalid_request', error_description: 'token must not carry a Bearer prefix' });
      }
      const nativeBearer = await revoke({ client_id: nativeClient, token: 'Bearer native-device-a' });
      expect((await oauthError(nativeBearer)).error).toBe('invalid_request');
      expect(await tokenState()).toEqual(seededState);

      // Without the interceptor the provider strips the prefix and runs the
      // revoked-token branch.
      await providerRevoke({ client_id: nativeClient, token: 'Bearer ordinary-revoked' });
      expect((await tokenState()).refresh.map((row) => row.id)).toEqual(['ordinary-live', 'ordinary-revoked']);
    });

    test('same client: the native client\'s own revoked ordinary token cannot delete its native devices\' tokens', async () => {
      // Issued to Exo before delegation was enabled, since revoked. Not
      // native, and owned by the requesting client.
      await seedRefreshToken('native-client-legacy', 'native-client-legacy', nativeClient, {
        scopes: ['openid', 'offline_access'], revoked: true,
      });
      const state = await tokenState();
      const grants = await prisma.tinyCloudNativeGrant.findMany({ orderBy: { id: 'asc' } });
      for (const hint of hints) {
        const response = await revoke({ client_id: nativeClient, token: 'native-client-legacy', ...(hint ? { token_type_hint: hint } : {}) });
        expect(response.status, String(hint)).toBe(400);
        expect(await oauthError(response)).toEqual(unsupported);
      }
      // Still native-capable once delegation is disabled: its grants remain.
      expect((await adminRequest('PATCH', `/clients/${nativeClient}`, { tinycloudNativeDelegation: null })).status).toBe(200);
      try {
        expect(await oauthError(await revoke({ client_id: nativeClient, token: 'native-client-legacy' }))).toEqual(unsupported);
      } finally {
        expect((await adminRequest('PATCH', `/clients/${nativeClient}`, { tinycloudNativeDelegation: ceiling })).status).toBe(200);
      }
      expect(await tokenState()).toEqual(state);
      expect(await prisma.tinyCloudNativeGrant.findMany({ orderBy: { id: 'asc' } })).toEqual(grants);

      await providerRevoke({ client_id: nativeClient, token: 'native-client-legacy' });
      expect((await tokenState()).refresh.map((row) => row.id)).toEqual(['ordinary-live', 'ordinary-revoked']);
    });

    test('a native-capable client revokes only its own access tokens through the provider', async () => {
      await seedAccessToken('native-plain-access', nativeClient, ['openid'], null);
      await seedAccessToken('ordinary-access', ordinaryClient, ['openid'], 'ordinary-live');
      await prisma.oauthRefreshToken.update({ where: { id: 'native-b' }, data: { revoked: new Date() } });
      const state = await tokenState();
      for (const token of [
        'native-device-a', 'native-device-b', 'native-device-a-rotated', // native refresh tokens
        'ordinary-live', 'ordinary-revoked', // refresh tokens of another client
        'ordinary-access', // another client's access token
        'never-issued', // not found
      ]) {
        for (const hint of hints) {
          const response = await revoke({ client_id: nativeClient, token, ...(hint ? { token_type_hint: hint } : {}) });
          expect(response.status, `${token} ${hint}`).toBe(400);
          expect(await oauthError(response), `${token} ${hint}`).toEqual(unsupported);
        }
      }
      expect(await tokenState()).toEqual(state);

      // Its own access tokens, native or not, pass; the provider deletes only them.
      for (const token of ['native-a-access', 'native-plain-access']) {
        const response = await revoke({ client_id: nativeClient, token, token_type_hint: 'access_token' });
        expect(response.status, token).toBe(200);
      }
      expect(await tokenState()).toEqual({ ...state, access: ['ordinary-access'] });
    });

    test('ordinary clients: native refresh tokens are unsupported, other clients\' tokens are refused', async () => {
      await prisma.oauthRefreshToken.update({ where: { id: 'native-b' }, data: { revoked: new Date() } });
      const state = await tokenState();
      for (const token of ['native-device-a', 'native-device-b', 'native-device-a-rotated']) {
        for (const hint of hints) {
          const response = await revoke({ client_id: ordinaryClient, token, ...(hint ? { token_type_hint: hint } : {}) });
          expect(await oauthError(response), `${token} ${hint}`).toEqual(unsupported);
        }
      }
      const otherAccess = await revoke({ client_id: ordinaryClient, token: 'native-a-access', token_type_hint: 'access_token' });
      expect(otherAccess.status).toBe(400);
      expect(await oauthError(otherAccess)).toEqual(notIssued);
      expect(await tokenState()).toEqual(state);
    });

    test('duplicate keys and malformed Basic credentials are refused', async () => {
      const duplicate = await form('/api/auth/oauth2/revoke',
        `client_id=${ordinaryClient}&token=ordinary-live&client_id=${nativeClient}`);
      expect(duplicate.status).toBe(400);
      const malformed = await revoke(
        { token: 'ordinary-revoked' },
        { authorization: `Basic ${Buffer.from(`${nativeClient}:x`).toString('base64url')}-` },
      );
      expect(malformed.status).toBe(401);
      expect(await tokenState()).toEqual(seededState);
    });

    test('an ordinary client\'s own access and refresh tokens still go to the provider', async () => {
      await seedAccessToken('ordinary-access', ordinaryClient, ['openid'], 'ordinary-live');
      const access = await revoke({ client_id: ordinaryClient, token: 'ordinary-access', token_type_hint: 'access_token' });
      expect(access.status).toBe(200);
      const ordinary = await revoke({ client_id: ordinaryClient, token: 'ordinary-live', token_type_hint: 'refresh_token' });
      expect(ordinary.status).toBe(200);
      expect(await tokenState()).toEqual({
        refresh: [
          { id: 'native-a', revoked: false },
          { id: 'native-b', revoked: false },
          { id: 'ordinary-live', revoked: true },
          { id: 'ordinary-revoked', revoked: true },
        ],
        access: ['native-a-access'],
      });
    });

    test('RFC 7009: an unknown token gets 200 with no side effects once the client validates, whatever the hint', async () => {
      for (const hint of hints) {
        const unknown = await revoke({ client_id: ordinaryClient, token: 'never-issued', ...(hint ? { token_type_hint: hint } : {}) });
        expect(unknown.status, String(hint)).toBe(200);
        expect(await unknown.text(), String(hint)).toBe('');
      }
      expect(await tokenState()).toEqual(seededState);
      // Client validation still comes first and is not masked.
      const unknownClient = await revoke({ client_id: 'no-such-client', token: 'never-issued' });
      expect(unknownClient.status).toBe(400);
      expect((await oauthError(unknownClient)).error).toBe('invalid_client');
      expect(await tokenState()).toEqual(seededState);
    });

    test('RFC 7009: unknown JWT-shaped and malformed tokens get 200 under every hint', async () => {
      const segment = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
      const jwtShaped = [
        // No kid: the provider's own JWT verification throws `Missing jwt kid`.
        'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmb28ifQ.invalid',
        `${segment({ alg: 'EdDSA', kid: 'no-such-key' })}.${segment({ sub: alice })}.c2lnbmF0dXJl`,
        `${segment({ alg: 'ES256' })}.${segment({ exp: 1 })}.x`,
        `${segment({ alg: 'none' })}.${segment({ sub: alice })}.`,
      ];
      const malformed = ['a.b', 'a.b.c.d', '....', 'eyJ.eyJ.x', 'not a token ü', 'x'.repeat(4096)];
      for (const token of [...jwtShaped, ...malformed]) {
        for (const hint of hints) {
          const response = await revoke({ client_id: ordinaryClient, token, ...(hint ? { token_type_hint: hint } : {}) });
          expect(response.status, `${token.slice(0, 40)} ${hint}`).toBe(200);
          expect(await response.text(), `${token.slice(0, 40)} ${hint}`).toBe('');
        }
      }
      expect(await tokenState()).toEqual(seededState);
      // The client is still validated first.
      const unknownClient = await revoke({ client_id: 'no-such-client', token: jwtShaped[0]! });
      expect((await oauthError(unknownClient)).error).toBe('invalid_client');
      // A native-capable client still gets unsupported_token_type.
      expect((await oauthError(await revoke({ client_id: nativeClient, token: jwtShaped[0]! }))).error)
        .toBe('unsupported_token_type');
    });

    test('a database failure during an unknown-token revoke stays a 5xx', async () => {
      await prisma.$executeRawUnsafe('ALTER TABLE "oauth_refresh_token" RENAME TO "oauth_refresh_token_offline"');
      try {
        for (const token of ['never-issued', 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmb28ifQ.invalid']) {
          const response = await revoke({ client_id: ordinaryClient, token });
          expect(response.status, token).toBe(500);
        }
      } finally {
        await prisma.$executeRawUnsafe('ALTER TABLE "oauth_refresh_token_offline" RENAME TO "oauth_refresh_token"');
      }
      expect((await revoke({ client_id: ordinaryClient, token: 'never-issued' })).status).toBe(200);
      expect(await tokenState()).toEqual(seededState);
    });
  });

  describe(`public protocol CORS and discovery (${backend})`, () => {
    const origins = ['capacitor://localhost', 'https://localhost'];
    const publicEndpoints = ['/api/auth/oauth2/token', '/api/auth/oauth2/par', '/api/auth/oauth2/tinycloud/renew', '/api/auth/oauth2/tinycloud/revoke'];

    test('discovery answers native WebView origins without credentials and advertises the native endpoints', async () => {
      for (const origin of origins) {
        for (const path of [
          '/.well-known/oauth-authorization-server/api/auth',
          '/.well-known/oauth-authorization-server',
          '/.well-known/openid-configuration',
          '/api/auth/.well-known/openid-configuration',
        ]) {
          const response = await call(path, { headers: { origin } });
          expect(response.status, path).toBe(200);
          expect(response.headers.get('access-control-allow-origin'), path).toBe('*');
          expect(response.headers.get('access-control-allow-credentials'), path).toBeNull();
          expect(response.headers.get('access-control-expose-headers'), path).toBe('Retry-After');
        }
      }
      const metadata = await (await call('/.well-known/oauth-authorization-server/api/auth')).json() as Record<string, string>;
      expect(metadata.issuer).toBe(ISSUER);
      expect(metadata.token_endpoint).toBe(`${ISSUER}/oauth2/token`);
      expect(metadata.pushed_authorization_request_endpoint).toBe(`${ISSUER}/oauth2/par`);
      expect(metadata.tinycloud_delegation_renew_endpoint).toBe(`${ISSUER}/oauth2/tinycloud/renew`);
      expect(metadata.tinycloud_delegation_revocation_endpoint).toBe(`${ISSUER}/oauth2/tinycloud/revoke`);
      for (const endpoint of [metadata.authorization_endpoint, metadata.token_endpoint, metadata.pushed_authorization_request_endpoint]) {
        expect(new URL(endpoint!).origin).toBe(API);
      }
    });

    test('preflight and POST on the public endpoints allow any origin and the session proof header', async () => {
      for (const origin of origins) {
        for (const path of publicEndpoints) {
          const preflight = await call(path, {
            method: 'OPTIONS',
            headers: {
              origin,
              'access-control-request-method': 'POST',
              'access-control-request-headers': 'content-type,openkey-session-proof',
            },
          });
          expect(preflight.status, path).toBe(204);
          expect(preflight.headers.get('access-control-allow-origin'), path).toBe('*');
          expect(preflight.headers.get('access-control-allow-credentials'), path).toBeNull();
          expect(preflight.headers.get('access-control-allow-headers')?.toLowerCase(), path).toContain('openkey-session-proof');
          expect(preflight.headers.get('access-control-allow-methods'), path).toContain('POST');

          const post = await form(path, 'grant_type=client_credentials', { origin });
          expect(post.headers.get('access-control-allow-origin'), path).toBe('*');
          expect(post.headers.get('access-control-allow-credentials'), path).toBeNull();
          expect(post.headers.get('access-control-expose-headers'), path).toBe('Retry-After');
        }
      }
    });

    test('Retry-After on a public endpoint is readable from capacitor://localhost', async () => {
      // No O2 route emits Retry-After yet, so a stub renew route sends the
      // 503 that renew will send, behind the production CORS middleware.
      const { Hono } = await import('hono');
      const { protocolAwareCors } = await import('../apps/api/src/services/native-delegation/public-protocol');
      const probe = new Hono();
      probe.use('*', protocolAwareCors(async (_c, next) => { await next(); }));
      probe.post('/api/auth/oauth2/tinycloud/renew', (c) =>
        c.json({ error: 'temporarily_unavailable' }, 503, { 'Retry-After': '2' }));
      const unavailable = await probe.fetch(new Request(`${API}/api/auth/oauth2/tinycloud/renew`, {
        method: 'POST', headers: { origin: 'capacitor://localhost' },
      }));
      expect(unavailable.status).toBe(503);
      expect(unavailable.headers.get('access-control-allow-origin')).toBe('*');
      const exposed = (unavailable.headers.get('access-control-expose-headers') ?? '').split(',').map((name) => name.trim().toLowerCase());
      expect(exposed).toContain('retry-after');
      expect(unavailable.headers.get('retry-after')).toBe('2');
    });

    test('cookie-authenticated and other routes keep the restricted credentialed policy', async () => {
      for (const path of [
        '/api/auth/oauth2/consent',
        '/api/auth/oauth2/delete-consent',
        '/api/auth/oauth2/revoke',
        '/api/auth/get-session',
        '/api/oauth/tinycloud/requests/request-id/prepare',
        '/api/account/apps',
        '/api/auth/oauth2/token/',
      ]) {
        for (const origin of origins) {
          const preflight = await call(path, {
            method: 'OPTIONS',
            headers: { origin, 'access-control-request-method': 'POST' },
          });
          expect(preflight.headers.get('access-control-allow-origin'), `${path} ${origin}`).not.toBe('*');
          expect(preflight.headers.get('access-control-allow-origin'), `${path} ${origin}`).not.toBe(origin);
        }
        const trusted = await call(path, {
          method: 'OPTIONS',
          headers: { origin: WEB_ORIGIN, 'access-control-request-method': 'POST' },
        });
        expect(trusted.headers.get('access-control-allow-origin'), path).toBe(WEB_ORIGIN);
        expect(trusted.headers.get('access-control-allow-credentials'), path).toBe('true');
      }
    });
  });

  describe(`consent withdrawal triggers (${backend})`, () => {
    async function seedWithdrawalFixture() {
      await prisma.oauthConsent.createMany({ data: [
        { id: 'consent-native', userId: alice, clientId: nativeClient, scopes: ['openid', 'offline_access', DELEGATION] },
        { id: 'consent-ordinary', userId: alice, clientId: ordinaryClient, scopes: ['openid', 'offline_access'] },
        { id: 'consent-bob', userId: bob, clientId: nativeClient, scopes: ['openid', 'offline_access', DELEGATION] },
      ] });
      await seedRefreshToken('bob-native', 'bob-native', nativeClient, { userId: bob });
      await seedGrant('grant-bob', nativeClient, { userId: bob, current: 'bob-native' });
      // A rotated device: the previous token row is still present (revoked).
      await seedRefreshToken('native-a-old', 'native-device-a-rotated', nativeClient, { revoked: true });
      const request = (id: string, status: string, userId = alice) => ({
        id, clientId: nativeClient, redirectUri: NATIVE_REDIRECT, state: 's', codeChallenge: 'c',
        scopes: ['openid', 'offline_access', DELEGATION], sessionDid: 'did:key:z', sessionJwk: {}, sessionJkt: 'j',
        requestedPermissions: [], ttlSeconds: 3600, status, userId,
        requestUriExpiresAt: new Date(Date.now() + 90_000), expiresAt: new Date(Date.now() + 600_000),
      });
      await prisma.tinyCloudNativeRequest.createMany({ data: [
        request('req-pending', 'PENDING'),
        request('req-resolved', 'RESOLVED'),
        request('req-approved', 'APPROVED'),
        request('req-denied', 'DENIED'),
        request('req-redeemed', 'REDEEMED'),
        request('req-bob', 'APPROVED', bob),
      ] });
    }

    async function withdrawalState() {
      const [generation, requests, grants, refresh, access] = await Promise.all([
        prisma.tinyCloudNativeConsentGeneration.findMany({ orderBy: [{ userId: 'asc' }, { clientId: 'asc' }] }),
        prisma.tinyCloudNativeRequest.findMany({ select: { id: true, status: true }, orderBy: { id: 'asc' } }),
        prisma.tinyCloudNativeGrant.findMany({ select: { id: true, status: true, revokedReason: true }, orderBy: { id: 'asc' } }),
        prisma.oauthRefreshToken.findMany({ select: { id: true }, orderBy: { id: 'asc' } }),
        prisma.oauthAccessToken.findMany({ select: { id: true }, orderBy: { id: 'asc' } }),
      ]);
      return {
        generation: generation.map((row) => ({ userId: row.userId, clientId: row.clientId, generation: row.generation })),
        requests: Object.fromEntries(requests.map((row) => [row.id, row.status])),
        grants: Object.fromEntries(grants.map((row) => [row.id, `${row.status}:${row.revokedReason ?? ''}`])),
        refresh: refresh.map((row) => row.id),
        access: access.map((row) => row.id),
      };
    }

    const withdrawnForAlice = () => ({
      generation: [{ userId: alice, clientId: nativeClient, generation: 1n }],
      requests: {
        'req-approved': 'WITHDRAWN', 'req-bob': 'APPROVED', 'req-denied': 'DENIED',
        'req-pending': 'PENDING', 'req-redeemed': 'REDEEMED', 'req-resolved': 'WITHDRAWN',
      },
      grants: { 'grant-a': 'REVOKED:consent_withdrawn', 'grant-b': 'REVOKED:consent_withdrawn', 'grant-bob': 'ACTIVE:' },
      refresh: ['bob-native', 'ordinary-live', 'ordinary-revoked'],
      access: [],
    });

    test('deleting consent through the provider endpoint bumps the generation and revokes grants and tokens', async () => {
      await seedWithdrawalFixture();
      const response = await call('/api/auth/oauth2/delete-consent', {
        method: 'POST',
        headers: { cookie, origin: WEB_ORIGIN, 'content-type': 'application/json' },
        body: JSON.stringify({ id: 'consent-native' }),
      });
      expect(response.status).toBe(200);
      expect(await withdrawalState()).toEqual(withdrawnForAlice());

      // Re-consent never resets the generation; a second withdrawal bumps it.
      await prisma.oauthConsent.create({ data: {
        id: 'consent-native-2', userId: alice, clientId: nativeClient, scopes: ['openid', DELEGATION],
      } });
      expect((await withdrawalState()).generation).toEqual([{ userId: alice, clientId: nativeClient, generation: 1n }]);
      await prisma.oauthConsent.delete({ where: { id: 'consent-native-2' } });
      expect((await withdrawalState()).generation).toEqual([{ userId: alice, clientId: nativeClient, generation: 2n }]);
    });

    test('withdrawing the scope through update-consent has the same effect; other updates do not', async () => {
      await seedWithdrawalFixture();
      const update = (scopes: string[]) => call('/api/auth/oauth2/update-consent', {
        method: 'POST',
        headers: { cookie, origin: WEB_ORIGIN, 'content-type': 'application/json' },
        body: JSON.stringify({ id: 'consent-native', update: { scopes } }),
      });
      const before = await withdrawalState();
      expect((await update(['openid', 'offline_access', DELEGATION, 'email'])).status).toBe(200);
      expect(await withdrawalState()).toEqual(before);
      expect((await update(['openid', 'offline_access'])).status).toBe(200);
      expect(await withdrawalState()).toEqual(withdrawnForAlice());
    });

    test('a NULL scope array, a moved consent row and a user cascade all withdraw', async () => {
      await seedWithdrawalFixture();
      await prisma.$executeRawUnsafe(`UPDATE "oauth_consent" SET "scopes" = NULL WHERE "id" = 'consent-native'`);
      expect(await withdrawalState()).toEqual(withdrawnForAlice());

      await prisma.$executeRawUnsafe(`UPDATE "oauth_consent" SET "clientId" = '${ordinaryClient}' WHERE "id" = 'consent-bob'`);
      const moved = await withdrawalState();
      expect(moved.grants['grant-bob']).toBe('REVOKED:consent_withdrawn');
      expect(moved.refresh).toEqual(['ordinary-live', 'ordinary-revoked']);
      expect(moved.generation).toContainEqual({ userId: bob, clientId: nativeClient, generation: 1n });

      await prisma.user.create({ data: { id: 'tc773-carol', email: 'carol@example.test', emailVerified: true } });
      await prisma.oauthConsent.create({ data: {
        id: 'consent-carol', userId: 'tc773-carol', clientId: nativeClient, scopes: [DELEGATION],
      } });
      await prisma.user.delete({ where: { id: 'tc773-carol' } });
      expect(await prisma.oauthConsent.count({ where: { userId: 'tc773-carol' } })).toBe(0);
      expect(await prisma.tinyCloudNativeConsentGeneration.findUnique({
        where: { userId_clientId: { userId: 'tc773-carol', clientId: nativeClient } },
      })).toMatchObject({ generation: 1n });
    });

    test('the SIWE nonce is fixed once set and must be 8-64 alphanumerics', async () => {
      await seedWithdrawalFixture();
      const setNonce = (id: string, nonce: string | null) => Promise.resolve(prisma.tinyCloudNativeRequest.update({
        where: { id }, data: { siweNonce: nonce },
      }));
      // First prepare writes the server nonce; later revisions rewrite the
      // same value.
      await setNonce('req-resolved', 'srvNonce0123456789');
      await setNonce('req-resolved', 'srvNonce0123456789');
      await expect(setNonce('req-resolved', 'otherNonce0123')).rejects.toThrow();
      await expect(setNonce('req-resolved', null)).rejects.toThrow();
      await expect(setNonce('req-approved', 'short')).rejects.toThrow();
      await expect(setNonce('req-approved', 'has-a-dash-1234')).rejects.toThrow();
      await prisma.tinyCloudNativeRequest.update({ where: { id: 'req-approved' }, data: { status: 'WITHDRAWN' } });
      expect(await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: 'req-resolved' } }))
        .toMatchObject({ siweNonce: 'srvNonce0123456789' });
    });

    test('statuses outside the closed set are rejected', async () => {
      await seedWithdrawalFixture();
      await expect(Promise.resolve(prisma.$executeRawUnsafe(`UPDATE "tinycloud_native_grant" SET "status" = 'PAUSED' WHERE "id" = 'grant-a'`)))
        .rejects.toThrow();
      await expect(Promise.resolve(prisma.$executeRawUnsafe(`UPDATE "tinycloud_native_request" SET "status" = 'DONE' WHERE "id" = 'req-pending'`)))
        .rejects.toThrow();
    });
  });
}
