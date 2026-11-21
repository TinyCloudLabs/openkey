// TC-3232: the switch-on path itself. Every other API suite runs with the Terms release pinned to "no
// version" (terms-release-off.ts), and the Terms suite sets its own. This one boots the API on the release
// file as checked in: an account that has not accepted is refused with 403 `terms_required`, and an
// app-review account is recorded as accepting the shipped version at start. Runs in a child process with
// OPENKEY_TEST_REAL_TERMS_RELEASE=1, which keeps the real file.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_TEST_REAL_TERMS_RELEASE !== '1') {
  test('the shipped Terms release gates an unaccepted account', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_TEST_REAL_TERMS_RELEASE: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'terms-shipped-release-isolated-test-secret',
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: 'https://openkey.test',
        CORS_ORIGIN: 'https://openkey.test',
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
  const api = 'https://api.openkey.test';
  const web = 'https://openkey.test';
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let secret: string;
  let cookieName: string;
  let shipped: { version: string; textSha256: string };
  let initializeReviewers: (database: PrismaClient) => Promise<void>;
  let hasAcceptedTerms: (database: PrismaClient, userId: string) => Promise<boolean>;

  beforeAll(async () => {
    shipped = JSON.parse(await readFile(join(root, 'apps/api/src/terms-release.json'), 'utf8'));
    directory = await mkdtemp(join(tmpdir(), 'openkey-terms-shipped-'));
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
    // The API modules open their database when loaded, so they are imported (dynamically) after DATABASE_URL is set.
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    ({ initializeReviewers } = await import('../services/reviewer-accounts'));
    ({ hasAcceptedTerms } = await import('../services/terms'));
    const context = await authModule.auth.$context;
    secret = context.secret;
    cookieName = context.authCookies.sessionToken.name;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  async function account(label: string) {
    const userId = `terms-shipped-${label}-${randomUUID()}`;
    const token = randomUUID();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    await prisma.ethereumKey.create({ data: { userId, address: `0x${randomUUID().replace(/-/g, '').padEnd(40, '0').slice(0, 40)}`, publicKey: '0x1', keyType: 'EXTERNAL' } });
    await prisma.session.create({ data: { id: `session-${userId}`, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    return { userId, cookie };
  }

  const get = (path: string, cookie: string) => app.fetch(new Request(`${api}${path}`, { headers: { cookie, origin: web } }));

  test('an account that has not accepted is refused, and the screen can read the shipped version', async () => {
    const { cookie } = await account('new');
    const refused = await get('/api/keys', cookie);
    expect(refused.status, await refused.clone().text()).toBe(403);
    expect(await refused.json()).toMatchObject({ error: 'terms_required', terms_url: `${web}/auth/terms` });
    const status = await get('/api/account/terms', cookie);
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ version: shipped.version, requiresAcceptance: true, previouslyAccepted: false });
  });

  test('an app-review account is recorded as accepting the shipped version at start', async () => {
    const { userId } = await account('reviewer');
    await prisma.reviewerAccount.update({ where: { store: 'apple' }, data: { userId } });
    try {
      expect(await hasAcceptedTerms(prisma, userId)).toBe(false);
      await initializeReviewers(prisma);
      const rows = await prisma.termsAcceptance.findMany({ where: { userId } });
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ version: shipped.version, textSha256: shipped.textSha256, surface: 'reviewer_seed' });
      expect(await hasAcceptedTerms(prisma, userId)).toBe(true);
    } finally {
      await prisma.reviewerAccount.update({ where: { store: 'apple' }, data: { userId: null } });
    }
  });

  // Seeing what you hold before deleting the account: an account that has not accepted can list its secrets'
  // names and read its variables (names and values) with its browser session, and nothing else about them.
  describe('reading your own secrets and variables before agreeing', () => {
    let writes: string[];
    beforeAll(async () => {
      const { tinyCloudService } = await import('../services/tinycloud-service');
      const service = tinyCloudService as unknown as Record<string, unknown>;
      service.isEnabledForUser = async () => true;
      service.listSecrets = async () => [{ name: 'API_TOKEN', createdAt: '2026-11-20T00:00:00.000Z' }];
      service.listVariables = async () => [{ name: 'REGION', value: 'eu', createdAt: '2026-11-20T00:00:00.000Z' }];
      for (const method of ['putSecret', 'deleteSecret', 'putVariable', 'deleteVariable', 'enableForUser']) {
        service[method] = async () => { writes.push(method); return { createdAt: 'x', spaceId: 'x' }; };
      }
    });
    beforeEach(() => { writes = []; });

    const send = (method: string, path: string, headers: Record<string, string>, body?: unknown) =>
      app.fetch(new Request(`${api}${path}`, {
        method, headers: { origin: web, ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
      }));

    test('an account that has not accepted can read its own secrets and variables', async () => {
      const { cookie } = await account('reader');
      const secrets = await send('GET', '/api/secrets', { cookie });
      expect(secrets.status).toBe(200);
      expect(await secrets.json()).toEqual({ secrets: [{ name: 'API_TOKEN', createdAt: '2026-11-20T00:00:00.000Z' }] });
      const variables = await send('GET', '/api/variables', { cookie });
      expect(variables.status).toBe(200);
      expect(await variables.json()).toEqual({ variables: [{ name: 'REGION', value: 'eu', createdAt: '2026-11-20T00:00:00.000Z' }] });
      const status = await send('GET', '/api/secrets/status', { cookie });
      expect(status.status).toBe(200);
      expect(await status.json()).toEqual({ enabled: true, secretCount: 1, variableCount: 1 });
    });

    test('an account that has not accepted cannot write them', async () => {
      const { cookie } = await account('writer');
      const attempts: Array<[string, string, unknown?]> = [
        ['POST', '/api/secrets/enable'],
        ['POST', '/api/secrets', { name: 'NEW', value: 'v' }],
        ['PUT', '/api/secrets/API_TOKEN', { value: 'v' }],
        ['DELETE', '/api/secrets/API_TOKEN'],
        ['POST', '/api/variables', { name: 'NEW', value: 'v' }],
        ['PUT', '/api/variables/REGION', { value: 'us' }],
        ['DELETE', '/api/variables/REGION'],
      ];
      for (const [method, path, body] of attempts) {
        const response = await send(method, path, { cookie }, body);
        expect(response.status, `${method} ${path}`).toBe(403);
        expect(await response.json(), `${method} ${path}`).toMatchObject({ error: 'terms_required' });
      }
      expect(writes).toEqual([]);
    });

    test('a session token or an app token for an account that has not accepted cannot read them', async () => {
      const { userId, cookie } = await account('token');
      const token = decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1));
      for (const path of ['/api/secrets', '/api/variables', '/api/secrets/status']) {
        // The account's own session token, as a widget or CLI would hold it: refused until the account agrees.
        const bearer = await send('GET', path, { authorization: `Bearer ${token}` });
        expect(bearer.status, path).toBe(403);
        expect(await bearer.json(), path).toMatchObject({ error: 'terms_required' });
        // An OAuth access token or delegation is not a session at all.
        const appToken = await send('GET', path, { authorization: `Bearer ${randomUUID()}` });
        expect(appToken.status, path).toBe(401);
      }
      // Once that account has agreed, its token reads its data.
      await prisma.termsAcceptance.create({
        data: { id: randomUUID(), userId, documentId: 'terms', version: shipped.version, textSha256: shipped.textSha256, surface: 'web', appVersion: 'test' },
      });
      const accepted = await send('GET', '/api/secrets', { authorization: `Bearer ${token}` });
      expect(accepted.status).toBe(200);
    });
  });
}
