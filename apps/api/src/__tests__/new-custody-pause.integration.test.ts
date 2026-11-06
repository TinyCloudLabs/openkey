import { afterAll, beforeAll, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { verifyMessage } from 'viem';
import type { Hex } from 'viem';
import { z } from 'zod';
import type { PrismaClient } from '@openkey/db';
import type { auth as authInstance } from '../auth';
import type appInstance from '../index';

const root = resolve(import.meta.dir, '../../../..');
if (!process.env.OPENKEY_CUSTODY_PAUSE_TEST_CHILD) {
  test('custody pause on the real auth adapter, routes and tracked database', async () => {
    const home = await mkdtemp(join(tmpdir(), 'openkey-custody-test-'));
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: root,
        env: { ...process.env, HOME: home, TC_HOME: join(home, 'tc'),
          OPENKEY_CUSTODY_PAUSE_TEST_CHILD: '1', OPENKEY_PAUSE_NEW_CUSTODY: 'false',
          NODE_ENV: 'test', TEE_MODE: 'development', DEV_SEALING_KEY: 'custody-pause-test-only-key',
          BETTER_AUTH_URL: 'http://localhost:3324', BETTER_AUTH_SECRET: 'custody-pause-isolated-auth-secret',
          WEBAUTHN_ORIGIN: 'http://localhost:5178', WEBAUTHN_RP_ID: 'localhost', CORS_ORIGIN: 'http://localhost:5178',
          TINYCLOUD_BOOTSTRAP_ON_SIGN: 'off', RESEND_API_KEY: '',
          GOOGLE_CLIENT_ID: 'test-google-client', GOOGLE_CLIENT_SECRET: 'test-google-secret',
          APPLE_CLIENT_ID: '', DATABASE_URL: `pglite:${join(home, 'db')}` },
        stdout: 'pipe', stderr: 'pipe',
      });
      const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect(code, stdout + stderr).toBe(0);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  }, 120_000);
} else {
  let prisma: PrismaClient;
  let auth: typeof authInstance;
  let app: typeof appInstance;
  const email = 'test@openkey.dev';
  const userResponse = z.object({ user: z.object({ id: z.string() }) });
  const hex = z.custom<Hex>((value) => typeof value === 'string' && /^0x[0-9a-f]+$/i.test(value));
  const post = (path: string, body: unknown, cookie?: string) => app.fetch(new Request(`http://localhost:3324${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://localhost:5178', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
  }));
  const counts = async () => ({ users: await prisma.user.count(), keys: await prisma.ethereumKey.count(), accounts: await prisma.account.count() });
  async function confirmationToken() {
    process.env.OPENKEY_PAUSE_NEW_CUSTODY = 'false';
    await post('/api/auth/email-otp/send-verification-otp', { email, type: 'sign-in' });
    const response = await post('/api/auth/sign-in/email-otp', { email, otp: '000000' });
    expect(response.status).toBe(403);
    const body = z.object({ code: z.string(), signupToken: z.string() }).parse(await response.json());
    expect(body.code).toBe('NEW_ACCOUNT_CONFIRMATION_REQUIRED');
    return body.signupToken;
  }
  beforeAll(async () => {
    const database = new PGlite(process.env.DATABASE_URL!.slice('pglite:'.length));
    try {
      const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    } finally { await database.close(); }
    // Auth/TEE singletons must load only after the isolated migrated DB exists.
    ({ auth, prisma } = await import('../auth'));
    app = (await import('../index')).default;
  }, 90_000);
  afterAll(async () => { await prisma?.$disconnect(); });

  test('confirmed email signup is 503 before any user or key insertion', async () => {
    const signupToken = await confirmationToken();
    process.env.OPENKEY_PAUSE_NEW_CUSTODY = 'true';
    const before = await counts();
    const response = await post('/api/auth/sign-up/email-otp', { email, signupToken });
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ code: 'NEW_CUSTODY_PAUSED' });
    expect(await counts()).toEqual(before);
  });

  test('social user creation rejects with the pause APIError before user or account insertion', async () => {
    process.env.OPENKEY_PAUSE_NEW_CUSTODY = 'true';
    const before = await counts();
    const context = await auth.$context;
    await expect(context.internalAdapter.createOAuthUser({ email: 'social@example.test', name: 'Social', emailVerified: true },
      { providerId: 'google', accountId: 'paused-google-user' })).rejects.toMatchObject({ statusCode: 503, body: { code: 'NEW_CUSTODY_PAUSED' } });
    expect(await counts()).toEqual(before);
  });

  test('social HTTP signup cannot bypass the hook even when Better Auth wraps its error', async () => {
    process.env.OPENKEY_PAUSE_NEW_CUSTODY = 'true';
    const context = await auth.$context;
    const provider = context.socialProviders.find((entry) => entry.id === 'google')!;
    // Only the external Google network/identity boundary is substituted.
    provider.verifyIdToken = async () => true;
    provider.getUserInfo = async () => ({ user: { id: 'google-new', email: 'google-new@example.test', name: 'Google new', emailVerified: true }, data: {} });
    const before = await counts();
    const response = await post('/api/auth/sign-in/social', { provider: 'google', idToken: { token: 'test-provider-token' } });
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ code: 'OAUTH_LINK_ERROR' });
    expect(await counts()).toEqual(before);
  });

  test('social signup works with pause off and existing social login still works with pause on', async () => {
    process.env.OPENKEY_PAUSE_NEW_CUSTODY = 'false';
    const context = await auth.$context;
    const provider = context.socialProviders.find((entry) => entry.id === 'google')!;
    provider.verifyIdToken = async () => true;
    provider.getUserInfo = async () => ({ user: { id: 'google-existing', email: 'google-existing@example.test', name: 'Google existing', emailVerified: true }, data: {} });
    const body = { provider: 'google', idToken: { token: 'test-provider-token' } };
    const signup = await post('/api/auth/sign-in/social', body);
    expect(signup.status, await signup.clone().text()).toBe(200);
    const { user } = userResponse.parse(await signup.json());
    expect(await prisma.ethereumKey.count({ where: { userId: user.id } })).toBe(1);
    process.env.OPENKEY_PAUSE_NEW_CUSTODY = 'true';
    const before = await counts();
    const login = await post('/api/auth/sign-in/social', body);
    expect(login.status, await login.clone().text()).toBe(200);
    expect(userResponse.parse(await login.json()).user.id).toBe(user.id);
    expect(await counts()).toEqual(before);
  });

  test('unset and false allow signup and creation; pause preserves login, Nostr retrieval and real signing', async () => {
    const signupToken = await confirmationToken();
    delete process.env.OPENKEY_PAUSE_NEW_CUSTODY;
    const signup = await post('/api/auth/sign-up/email-otp', { email, signupToken });
    expect(signup.status, await signup.clone().text()).toBe(200);
    const { user } = userResponse.parse(await signup.json());
    expect(await prisma.ethereumKey.count({ where: { userId: user.id } })).toBe(1);
    const cookie = signup.headers.getSetCookie().map((value) => value.split(';')[0]).join('; ');
    process.env.OPENKEY_PAUSE_NEW_CUSTODY = 'false';
    const generated = await post('/api/keys/generate', {}, cookie);
    expect(generated.status, await generated.clone().text()).toBe(201);
    const { key } = z.object({ key: z.object({ id: z.string(), address: hex }) }).parse(await generated.json());
    const nostr = await post('/api/keys/nostr', {}, cookie);
    expect(nostr.status, await nostr.clone().text()).toBe(201);
    const identity = await nostr.json();
    process.env.OPENKEY_PAUSE_NEW_CUSTODY = 'true';
    const before = await counts();
    const refused = await post('/api/keys/generate', {}, cookie);
    expect(refused.status).toBe(503);
    expect(await refused.json()).toMatchObject({ code: 'NEW_CUSTODY_PAUSED' });
    expect(await counts()).toEqual(before);
    const existing = await post('/api/keys/nostr', {}, cookie);
    expect(existing.status).toBe(200);
    expect(await existing.json()).toEqual(identity);
    await post('/api/auth/email-otp/send-verification-otp', { email, type: 'sign-in' });
    const login = await post('/api/auth/sign-in/email-otp', { email, otp: '000000' });
    expect(login.status, await login.clone().text()).toBe(200);
    expect(userResponse.parse(await login.json()).user.id).toBe(user.id);
    const signed = await post(`/api/keys/${key.id}/sign`, { message: 'Custody pause must preserve existing signing' }, cookie);
    expect(signed.status, await signed.clone().text()).toBe(200);
    const { signature } = z.object({ signature: hex }).parse(await signed.json());
    expect(await verifyMessage({ address: key.address, message: 'Custody pause must preserve existing signing', signature })).toBe(true);
  });
}
