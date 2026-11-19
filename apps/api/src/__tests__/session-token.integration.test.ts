import { expect, test } from 'bun:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';

// Bearer sessions are accepted only in their signed form, and OpenKey's pages read that form from
// /session-token. A fresh process avoids Bun's process-wide route/auth mocks in the unit lane.
if (!process.env.TC_SESSION_TOKEN_CHILD) {
  test('bearer sessions are accepted only signed; /session-token returns the signed form', async () => {
    const directory = await mkdtemp('/var/tmp/openkey-session-token-');
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: resolve(import.meta.dir, '../../../..'),
        env: { ...process.env, TC_SESSION_TOKEN_CHILD: directory, HOME: directory, TMPDIR: directory,
          BUN_INSTALL_CACHE_DIR: join(directory, 'bun-cache'), NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: 'http://localhost:3325', BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
          WEBAUTHN_ORIGIN: 'https://openkey.example', WEBAUTHN_RP_ID: 'localhost',
          CORS_ORIGIN: 'https://openkey.example,https://console.openkey.example', CONSOLE_ORIGIN: 'https://console.openkey.example',
          TINYCLOUD_BOOTSTRAP_ON_SIGN: 'off',
          RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
          DATABASE_URL: `pglite:${join(directory, 'db')}` },
        stdout: 'pipe', stderr: 'pipe',
      });
      const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect(code, stdout + stderr).toBe(0);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }, 120_000);
} else {
  test('signed bearer, unsigned bearer and /session-token', async () => {
    const directory = process.env.TC_SESSION_TOKEN_CHILD!;
    const root = resolve(import.meta.dir, '../../../..');
    const database = new PGlite(join(directory, 'db'));
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const migration of migrations) {
      await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    }
    await database.close();
    const { createPrismaClient } = await import('@openkey/db');
    const { auth } = await import('../auth');
    const app = (await import('../index')).default;
    const request = (url: string, init?: RequestInit) => app.fetch(new Request(url, init));
    const prisma = createPrismaClient();
    const authContext = await auth.$context;
    const api = process.env.BETTER_AUTH_URL!;
    const OPENKEY = 'https://openkey.example';

    // test@openkey.dev signs in with 000000 in development (auth.ts generateOTP).
    const userId = randomUUID();
    await prisma.user.create({ data: { id: userId, email: 'test@openkey.dev', emailVerified: true } });
    await request(`${api}/api/auth/email-otp/send-verification-otp`, {
      method: 'POST', headers: { origin: OPENKEY, 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'test@openkey.dev', type: 'sign-in' }),
    });
    const signIn = await request(`${api}/api/auth/sign-in/email-otp`, {
      method: 'POST', headers: { origin: OPENKEY, 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'test@openkey.dev', otp: '000000' }),
    });
    expect(signIn.status, await signIn.clone().text()).toBe(200);
    const issued = signIn.headers.get('set-auth-token')!;
    expect(issued).toContain('.');
    const rawToken = (await prisma.session.findFirstOrThrow({ where: { userId } })).token;
    const cookie = (await serializeSignedCookie(authContext.authCookies.sessionToken.name, rawToken, authContext.secret)).split(';')[0]!;

    async function sessionUser(headers: Record<string, string>) {
      const response = await request(`${api}/api/auth/get-session?disableRefresh=true`, { headers: { origin: OPENKEY, ...headers } });
      expect(response.status).toBe(200);
      return ((await response.json()) as { user?: { id: string } } | null)?.user?.id ?? null;
    }
    const tokenRoute = (headers: Record<string, string>) =>
      request(`${api}/api/auth/session-token`, { headers });

    // The signed form authenticates; the raw database token does not.
    expect(await sessionUser({ authorization: `Bearer ${issued}` })).toBe(userId);
    expect(await sessionUser({ authorization: `Bearer ${rawToken}` })).toBeNull();
    const keysWithRaw = await request(`${api}/api/keys`, { headers: { origin: OPENKEY, authorization: `Bearer ${rawToken}` } });
    expect(keysWithRaw.status).toBe(401);

    // /session-token: the cookie session's signed token, equal to what sign-in issued.
    const fromCookie = await tokenRoute({ origin: OPENKEY, cookie });
    expect(fromCookie.status).toBe(200);
    expect(fromCookie.headers.get('cache-control')).toBe('no-store');
    expect(fromCookie.headers.get('access-control-allow-origin')).toBe(OPENKEY);
    const { token } = (await fromCookie.json()) as { token: string };
    expect(token).toBe(issued);
    expect(await sessionUser({ authorization: `Bearer ${token}` })).toBe(userId);

    // The session read answers without the token.
    const read = await request(`${api}/api/auth/get-session?disableRefresh=true`, { headers: { origin: OPENKEY, cookie } });
    const readBody = (await read.json()) as { user: { id: string }; session: Record<string, unknown> };
    expect(readBody.user.id).toBe(userId);
    expect(readBody.session.userId).toBe(userId);
    expect('token' in readBody.session).toBe(false);

    // Never 404 (the web falls back to reading the session only on 404): no session is 401,
    // a bearer is refused, and a foreign origin is refused.
    expect((await tokenRoute({ origin: OPENKEY })).status).toBe(401);
    expect((await tokenRoute({ origin: OPENKEY, cookie, authorization: `Bearer ${issued}` })).status).toBe(403);
    expect((await tokenRoute({ origin: OPENKEY, authorization: `Bearer ${issued}` })).status).toBe(403);
    const foreign = await tokenRoute({ origin: 'https://attacker-site.example', cookie });
    expect(foreign.status).toBe(403);
    expect(foreign.headers.get('access-control-allow-origin')).toBeNull();
    // The console is on the credentialed CORS list but is not the account origin.
    expect((await tokenRoute({ origin: 'https://console.openkey.example', cookie })).status).toBe(403);
  }, 90_000);
}
