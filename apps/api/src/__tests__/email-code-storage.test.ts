import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';

// Email sign-in and step-up codes are stored as a keyed hash. Real auth,
// real routes and tracked migrations run in a separate process because API
// unit tests replace modules process-wide.
const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_EMAIL_CODE_TEST_CHILD !== '1') {
  test('email codes are not stored in plain text', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_EMAIL_CODE_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'email-code-storage-isolated-test-secret',
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: 'https://openkey.test',
        CORS_ORIGIN: 'https://openkey.test',
        RESEND_API_KEY: 'email-code-storage-resend-stub',
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
  const email = 'code-owner@example.test';
  const signInIdentifier = `sign-in-otp-${email}`;
  const mail: { to: string; html: string }[] = [];
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookie: string;
  let sessionId: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-email-code-'));
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
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.startsWith('https://api.resend.com/')) {
        const body = JSON.parse(String(init?.body ?? '{}')) as { to?: string | string[]; html?: string };
        mail.push({ to: Array.isArray(body.to) ? body.to[0]! : body.to ?? '', html: body.html ?? '' });
        return Response.json({ id: randomUUID() });
      }
      return originalFetch(input, init);
    }) as typeof fetch;
    // Loaded only now: the API and its Prisma client read DATABASE_URL at import time.
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    await prisma.user.create({ data: { id: 'code-owner', email, name: 'Code Owner', emailVerified: true } });
    const sessionToken = randomUUID();
    sessionId = 'code-owner-session';
    await prisma.session.create({ data: { id: sessionId, userId: 'code-owner', token: sessionToken, expiresAt: new Date(Date.now() + 3_600_000) } });
    const context = await authModule.auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  const post = (path: string, body: unknown, withSession = false) => app.fetch(new Request(`https://api.openkey.test${path}`, {
    method: 'POST',
    headers: { origin: 'https://openkey.test', 'content-type': 'application/json', ...(withSession ? { cookie } : {}) },
    body: JSON.stringify(body),
  }));
  const lastCode = () => {
    const code = /<p>(\d{6})<\/p>|>(\d{6})<\/p>/.exec(mail.at(-1)?.html ?? '');
    expect(code).not.toBeNull();
    return (code![1] ?? code![2])!;
  };
  const storedValue = async (identifier: string) =>
    (await prisma.verification.findFirstOrThrow({ where: { identifier: { startsWith: identifier } } })).value;
  const sendSignInCode = async () => {
    expect((await post('/api/auth/email-otp/send-verification-otp', { email, type: 'sign-in' })).status).toBe(200);
    return lastCode();
  };

  describe('sign-in codes', () => {
    test('the stored value is neither the mailed code nor its unkeyed hash, and the code signs in', async () => {
      const code = await sendSignInCode();
      const stored = await storedValue(signInIdentifier);
      expect(stored).not.toContain(code);
      for (const encoding of ['hex', 'base64url'] as const) {
        expect(stored).not.toContain(createHash('sha256').update(code).digest(encoding));
      }
      expect((await post('/api/auth/sign-in/email-otp', { email, otp: code })).status).toBe(200);
    });

    test('a resend inside the window invalidates the earlier code', async () => {
      const first = await sendSignInCode();
      let latest = await sendSignInCode();
      // Two random six-digit codes coincide one time in a million; a third send settles it.
      if (latest === first) latest = await sendSignInCode();
      expect(latest).not.toBe(first);
      expect((await post('/api/auth/sign-in/email-otp', { email, otp: first })).status).toBe(400);
      expect((await post('/api/auth/sign-in/email-otp', { email, otp: latest })).status).toBe(200);
    });

    test('a code stored in plain text is refused, and the next send replaces it', async () => {
      await prisma.verification.deleteMany({ where: { identifier: signInIdentifier } });
      await prisma.verification.create({ data: {
        id: randomUUID(), identifier: signInIdentifier, value: '123456:0', expiresAt: new Date(Date.now() + 300_000),
      } });
      expect((await post('/api/auth/sign-in/email-otp', { email, otp: '123456' })).status).toBe(400);
      const code = await sendSignInCode();
      expect((await post('/api/auth/sign-in/email-otp', { email, otp: code })).status).toBe(200);
    });
  });

  describe('account step-up codes', () => {
    const identifier = () => `openkey-account-step-up-otp:${sessionId}:`;

    test('the stored value does not contain the mailed code; a wrong code is refused and the right one accepted', async () => {
      expect((await post('/api/account/step-up/email-otp/send', { purpose: 'link' }, true)).status).toBe(200);
      const code = lastCode();
      expect(await storedValue(identifier())).not.toContain(code);
      const wrong = code === '000000' ? '000001' : '000000';
      expect((await post('/api/account/step-up/email-otp/verify', { code: wrong, purpose: 'link' }, true)).status).toBe(400);
      expect((await post('/api/account/step-up/email-otp/verify', { code, purpose: 'link' }, true)).status).toBe(200);
    });

    test('a code stored in plain text is refused', async () => {
      await prisma.verification.deleteMany({ where: { identifier: { startsWith: identifier() } } });
      await prisma.verification.create({ data: {
        id: randomUUID(), identifier: `${identifier()}${email}`, value: '123456:0', expiresAt: new Date(Date.now() + 300_000),
      } });
      expect((await post('/api/account/step-up/email-otp/verify', { code: '123456', purpose: 'link' }, true)).status).toBe(400);
    });
  });
}
