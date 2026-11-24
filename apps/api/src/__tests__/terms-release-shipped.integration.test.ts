// TC-3232: the switch-on path itself. Every other API suite runs with the Terms release pinned to "no
// version" (terms-release-off.ts), and the Terms suite sets its own. This one boots the API on the release
// file as checked in: an account that has not accepted is refused with 403 `terms_required`, and an
// app-review account is recorded as accepting the shipped version at start. Runs in a child process with
// OPENKEY_TEST_REAL_TERMS_RELEASE=1, which keeps the real file.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
// test-ruling TC-3766 openkey #684 apps/api/src/__tests__/terms-release-shipped.integration.test.ts (2026-11-22): yes to (1), with one addition. The existing cases are skipped only when the checked-in release has version === null, and they run unchanged when it's set again (the reverse PR restores them). Add one case that runs only when version === null: the API boots, GET /api/account/terms reports requiresAcceptance:false, and a token request to /api/keys is not 403 terms_required. Nothing else in the file changes.
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
  const unreleased = JSON.parse(readFileSync(join(root, 'apps/api/src/terms-release.json'), 'utf8')).version === null;
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

  test.skipIf(unreleased)('an account that has not accepted is refused, and the screen can read the shipped version', async () => {
    const { cookie } = await account('new');
    const refused = await get('/api/keys', cookie);
    expect(refused.status, await refused.clone().text()).toBe(403);
    expect(await refused.json()).toMatchObject({ error: 'terms_required', terms_url: `${web}/auth/terms` });
    const status = await get('/api/account/terms', cookie);
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ version: shipped.version, requiresAcceptance: true, previouslyAccepted: false });
  });

  test.skipIf(unreleased)('an app-review account is recorded as accepting the shipped version at start', async () => {
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
  describe.skipIf(unreleased)('reading your own secrets and variables before agreeing', () => {
    // The service stands in for the TinyCloud node: a session is open for an account once it is `open`, and the
    // lists fail without one, as they do after an API restart.
    let writes: string[];
    const open = new Set<string>();
    const restored: Array<{ userId: string; privateKey: string }> = [];
    beforeAll(async () => {
      const { tinyCloudService } = await import('../services/tinycloud-service');
      const service = tinyCloudService as unknown as Record<string, unknown>;
      const requireOpen = (userId: string) => { if (!open.has(userId)) throw new Error('TinyCloud not enabled for user'); };
      service.isEnabledForUser = async (userId: string) => open.has(userId);
      service.enableForUser = async (userId: string, privateKey: string) => {
        open.add(userId);
        restored.push({ userId, privateKey });
        return { spaceId: 'x' };
      };
      service.listSecrets = async (userId: string) => {
        requireOpen(userId);
        return [{ name: 'API_TOKEN', createdAt: '2026-11-20T00:00:00.000Z' }];
      };
      service.listVariables = async (userId: string) => {
        requireOpen(userId);
        return [{ name: 'REGION', value: 'eu', createdAt: '2026-11-20T00:00:00.000Z' }];
      };
      for (const method of ['putSecret', 'deleteSecret', 'putVariable', 'deleteVariable']) {
        service[method] = async () => { writes.push(method); return { createdAt: 'x' }; };
      }
    });
    beforeEach(() => { writes = []; });

    const send = (method: string, path: string, headers: Record<string, string>, body?: unknown) =>
      app.fetch(new Request(`${api}${path}`, {
        method, headers: { origin: web, ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
      }));

    test('an account that has not accepted can read its own secrets and variables', async () => {
      const { userId, cookie } = await account('reader');
      open.add(userId);
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

    test('after an API restart the lists restore the account\'s TinyCloud session themselves', async () => {
      const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
      const { userId, cookie } = await account('restore');
      const privateKey = generatePrivateKey();
      const sealingContext = randomBytes(32).toString('base64url');
      const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
      await prisma.ethereumKey.deleteMany({ where: { userId } });
      await prisma.ethereumKey.create({
        data: { userId, address: getAddressFromPrivateKey(privateKey), publicKey: '0x1', sealedBlob: await seal(privateKey, sealingKey), sealingContext, keyType: 'MANAGED' },
      });
      // The API has just restarted: this account's session is not open, and nothing has called /status.
      expect(open.has(userId)).toBe(false);
      for (const [path, key] of [['/api/secrets', 'secrets'], ['/api/variables', 'variables']] as const) {
        open.delete(userId);
        const listed = await send('GET', path, { cookie });
        expect(listed.status, path).toBe(200);
        expect(Object.keys(await listed.json()), path).toEqual([key]);
        expect(restored.at(-1), path).toEqual({ userId, privateKey: privateKey.replace(/^0x/, '') });
      }
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

    test('a session token or an app token sent in an Authorization header for an account that has not accepted cannot read them', async () => {
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
      open.add(userId);
      const accepted = await send('GET', '/api/secrets', { authorization: `Bearer ${token}` });
      expect(accepted.status).toBe(200);
    });
  });

  test.skipIf(!unreleased)('the checked-in release has no version, so nothing is gated', async () => {
    const { cookie } = await account('unreleased');
    const status = await get('/api/account/terms', cookie);
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ requiresAcceptance: false });
    const keys = await get('/api/keys', cookie);
    expect(keys.status, await keys.clone().text()).not.toBe(403);
    expect(await keys.clone().json().catch(() => ({}))).not.toMatchObject({ error: 'terms_required' });
  });
}
