import { afterAll, beforeAll, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { serializeSignedCookie } from 'better-call';
import { decodeJwt } from 'jose';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '..');
if (process.env.OPENKEY_IDENTITY_REFRESH_TEST_CHILD !== '1') {
  test('an identity refresh cannot gain manage-key scope', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: { ...process.env, OPENKEY_IDENTITY_REFRESH_TEST_CHILD: '1' },
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
  const callback = 'https://app.example.test/callback';
  const verifier = 'identity-refresh-pkce-verifier-0123456789012345678901';
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookie: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-identity-refresh-'));
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
    process.env.NODE_ENV = 'test';
    process.env.TEE_MODE = 'development';
    process.env.BETTER_AUTH_URL = issuer;
    process.env.BETTER_AUTH_SECRET = randomUUID();
    process.env.WEBAUTHN_RP_ID = 'openkey.test';
    process.env.WEBAUTHN_ORIGIN = 'https://openkey.test';
    process.env.CORS_ORIGIN = 'https://openkey.test';
    process.env.OAUTH_DYNAMIC_CLIENT_REGISTRATION = 'true';
    process.env.RESEND_API_KEY = '';
    process.env.GOOGLE_CLIENT_ID = '';
    process.env.GOOGLE_CLIENT_SECRET = '';
    const authModule = await import('../apps/api/src/auth');
    prisma = authModule.prisma;
    app = (await import('../apps/api/src/index')).default;
    await prisma.user.create({ data: { id: 'identity-owner', email: 'identity-owner@example.test', name: 'Owner', emailVerified: true } });
    const sessionToken = randomUUID();
    await prisma.session.create({ data: {
      id: 'identity-owner-session', userId: 'identity-owner', token: sessionToken, expiresAt: new Date(Date.now() + 3_600_000),
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

  test('confidential identity clients reject extra authorization scopes and receive no refresh token', async () => {
    const clientId = `ok_${randomUUID().replaceAll('-', '')}`;
    const clientSecret = randomUUID();
    await prisma.oauthClient.create({ data: {
      id: randomUUID(),
      clientId,
      clientSecret: createHash('sha256').update(clientSecret).digest('base64url'),
      name: 'Identity refresh test',
      redirectUris: [callback],
      scopes: ['openid', 'email', 'tinycloud:identity'],
      contacts: [],
      type: 'web',
      public: false,
      tokenEndpointAuthMethod: 'client_secret_basic',
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
    } });
    const authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;

    async function authorize(scope: string, state: string) {
      const query = new URLSearchParams({
        client_id: clientId, response_type: 'code', redirect_uri: callback,
        scope, state,
        code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256',
      });
      return call(`/oauth2/authorize?${query}`, {}, true);
    }

    for (const scope of ['openid email tinycloud:identity tinycloud:manage-key', 'openid email tinycloud:identity keys']) {
      const rejected = await authorize(scope, 'identity-scope-rejected');
      const error = rejected.status === 302
        ? new URL(rejected.headers.get('location')!, issuer).searchParams.get('error')
        : (await rejected.json() as { error?: string }).error;
      expect(error).toBe('invalid_scope');
    }

    const authorizeIdentity = await authorize('openid email tinycloud:identity', 'identity-refresh');
    expect(authorizeIdentity.status).toBe(302);
    const consentUrl = new URL(authorizeIdentity.headers.get('location')!, issuer);
    const consent = await call('/oauth2/consent', {
      method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://openkey.test' },
      body: JSON.stringify({ accept: true, oauth_query: consentUrl.searchParams.toString() }),
    }, true);
    expect(consent.status).toBe(200);
    const code = new URL((await consent.json() as { url: string }).url).searchParams.get('code')!;

    const exchange = await call('/oauth2/token', {
      method: 'POST', headers: { ...form, authorization },
      body: new URLSearchParams({
        client_id: clientId, grant_type: 'authorization_code', code,
        redirect_uri: callback, code_verifier: verifier,
      }),
    });
    expect(exchange.status).toBe(200);
    const issued = await exchange.json();
    expect(issued).not.toHaveProperty('refresh_token');
    expect(issued).toHaveProperty('access_token');
  });
}
