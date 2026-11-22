// The embedded OpenKey frame reads and agrees to the Terms with its session token (Bearer), through the whole API
// on PGlite with the tracked migrations. A token agrees only for a sign-in in the last 10 minutes, and the record
// keeps the session and the proof it stood on. Runs in a child process, as the other full-API tests do.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';
import { mockModules } from './mock-module';

const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_TERMS_EMBED_TEST_CHILD !== '1') {
  test('the embedded frame agrees to the Terms with its session token', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_TERMS_EMBED_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'terms-embed-acceptance-isolated-test-secret',
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: 'https://openkey.test',
        CORS_ORIGIN: 'https://openkey.test',
        TINYCLOUD_BOOTSTRAP_ON_SIGN: 'off',
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
  }, 300_000);
} else {
  const api = 'https://api.openkey.test';
  const web = 'https://openkey.test';
  const embedder = 'https://app.example.test';
  const VERSION = '2026-12-01';
  const SHA = 'b'.repeat(64);
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let secret: string;
  let cookieName: string;
  let counter = 0;

  // The checked-in terms-release.json, replaced by one object: the API reads it per call.
  const releaseFile: Record<string, unknown> = {
    version: VERSION, requiredVersion: null, textSha256: SHA, whatChanged: null, privacyChanged: false,
  };
  await mockModules({ '../terms-release.json': () => ({ default: releaseFile }) });

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-terms-embed-'));
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
    // Loaded after DATABASE_URL is set and the release file is replaced: the API modules open their database, and
    // bind the release file, when loaded.
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    const context = await authModule.auth.$context;
    secret = context.secret;
    cookieName = context.authCookies.sessionToken.name;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  const request = (path: string, init: RequestInit = {}) => app.fetch(new Request(`${api}${path}`, init));
  const post = (path: string, body: unknown, headers: Record<string, string>) => request(path, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
  });
  const frame = (bearer: string, origin = web) => ({ authorization: `Bearer ${bearer}`, origin });
  const acceptWith = (headers: Record<string, string>, body: unknown = { version: VERSION, embedOrigin: embedder }) =>
    post('/api/account/terms/accept', body, headers);
  const rows = (userId: string) => prisma.termsAcceptance.findMany({ where: { userId } });

  async function signedIn() {
    const n = ++counter;
    const userId = `terms-embed-user-${n}-${randomUUID()}`;
    const token = randomUUID();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    const session = await prisma.session.create({
      data: { id: `terms-embed-session-${n}`, userId, token, expiresAt: new Date(Date.now() + 86_400_000) },
    });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    // A bearer is the signed session token, as `set-auth-token` hands it out.
    return { userId, session, cookie, bearer: cookie.slice(cookie.indexOf('=') + 1) };
  }

  describe('the frame’s Terms', () => {
    test('a fresh sign-in reads the Terms and records an embed acceptance with its proof', async () => {
      const { userId, session, bearer } = await signedIn();
      const status = await request('/api/account/terms', { headers: frame(bearer) });
      expect(status.status).toBe(200);
      expect(await status.json()).toMatchObject({ version: VERSION, requiresAcceptance: true });

      const accepted = await acceptWith(frame(bearer));
      expect(accepted.status, await accepted.clone().text()).toBe(200);
      const [row] = await rows(userId);
      expect(row).toMatchObject({
        userId, version: VERSION, textSha256: SHA, surface: 'embed', sessionId: session.id, proof: 'session_created',
        proofAt: session.createdAt, requestOrigin: web, embedOriginClaimed: embedder,
      });
      const after = await request('/api/account/terms', { headers: frame(bearer) });
      expect(await after.json()).toMatchObject({ requiresAcceptance: false });
      expect((await request('/api/keys', { headers: frame(bearer) })).status).toBe(200);
    });

    test('a new account made from an email code agrees in the frame with the token it was given', async () => {
      const email = 'test@openkey.dev';
      await post('/api/auth/email-otp/send-verification-otp', { email, type: 'sign-in' }, { origin: web });
      const verified = await post('/api/auth/sign-in/email-otp', { email, otp: '000000' }, { origin: web });
      const { signupToken } = await verified.json() as { signupToken?: string };
      expect(typeof signupToken).toBe('string');
      const created = await post('/api/auth/sign-up/email-otp', { email, signupToken }, { origin: web });
      expect(created.status, await created.clone().text()).toBe(200);
      const bearer = created.headers.get('set-auth-token')!;
      expect(bearer).toContain('.');

      expect((await acceptWith(frame(bearer))).status).toBe(200);
      const user = await prisma.user.findUniqueOrThrow({ where: { email } });
      expect(await rows(user.id)).toEqual([expect.objectContaining({ surface: 'embed', proof: 'session_created' })]);
    });

    test('a reviewer session cannot agree with its token', async () => {
      const { userId, session, bearer } = await signedIn();
      await prisma.session.update({ where: { id: session.id }, data: { reviewerEpoch: 1 } });
      const refused = await acceptWith(frame(bearer));
      expect(refused.status).toBe(403);
      expect(await refused.json()).toEqual({ error: 'terms_step_up' });
      expect(await rows(userId)).toEqual([]);
    });

    test('a token from another site is refused', async () => {
      const { userId, bearer } = await signedIn();
      expect((await acceptWith(frame(bearer, 'https://attacker.example'))).status).toBe(403);
      expect(await rows(userId)).toEqual([]);
    });

    test('a token request names no surface or client; the browser cannot claim the frame’s surface', async () => {
      const { userId, bearer, cookie } = await signedIn();
      expect((await acceptWith(frame(bearer), { version: VERSION, surface: 'web' })).status).toBe(400);
      expect((await acceptWith(frame(bearer), { version: VERSION, clientId: 'any' })).status).toBe(400);
      expect((await acceptWith({ cookie, origin: web }, { version: VERSION, surface: 'embed' })).status).toBe(400);
      expect(await rows(userId)).toEqual([]);
    });

    test('an embedding origin that is not a web origin is not kept', async () => {
      const { userId, bearer } = await signedIn();
      expect((await acceptWith(frame(bearer), { version: VERSION, embedOrigin: 'javascript:alert(1)' })).status).toBe(200);
      expect((await rows(userId))[0]).toMatchObject({ surface: 'embed', embedOriginClaimed: null });
    });

    test('the browser records a web acceptance as before, with no frame audit', async () => {
      const { userId, cookie } = await signedIn();
      expect((await acceptWith({ cookie, origin: web }, { version: VERSION })).status).toBe(200);
      expect((await rows(userId))[0]).toMatchObject({
        surface: 'web', sessionId: null, proof: null, proofAt: null, requestOrigin: null, embedOriginClaimed: null,
      });
    });
  });
}
