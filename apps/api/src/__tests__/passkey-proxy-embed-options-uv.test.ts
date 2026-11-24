// The embedded sheet's passkey sign-in asks the authenticator to verify the person: the options the token proxy
// returns carry `userVerification: "required"`, because the proxy verifies every ceremony under the marker that
// refuses an assertion made without user verification. Better Auth's own options say "preferred", and the login
// page's cookie route keeps them. Runs against the real API on PGlite with the tracked migrations, in a child
// process: the API reads its relying party, origins and database when loaded.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { PrismaClient } from '@openkey/db';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';
import { createSoftPasskey, type SoftPasskey } from './soft-passkey';

const root = resolve(import.meta.dir, '../../../..');
const web = 'https://openkey.test';

if (process.env.OPENKEY_EMBED_OPTIONS_UV_CHILD !== '1') {
  test('the embedded passkey sign-in options require user verification', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_EMBED_OPTIONS_UV_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: web,
        CORS_ORIGIN: web,
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
  let directory: string;
  let prisma: PrismaClient;
  let auth: { handler: (request: Request) => Promise<Response> };
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  const originalFetch = globalThis.fetch;

  beforeAll(async () => {
    globalThis.fetch = ((input: RequestInfo | URL) => {
      const url = String(input instanceof Request ? input.url : input);
      return Promise.reject(new Error(`External network disabled in this test: ${url}`));
    }) as typeof fetch;
    directory = await mkdtemp(join(tmpdir(), 'openkey-embed-options-uv-'));
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
    auth = authModule.auth as unknown as typeof auth;
    app = (await import('../index')).default;
  }, 120_000);

  afterAll(async () => {
    globalThis.fetch = originalFetch;
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  async function passkeyOwner(): Promise<SoftPasskey> {
    const userId = randomUUID();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    return createSoftPasskey(prisma, userId, false, web);
  }

  const post = (path: string, body: unknown) =>
    app.fetch(new Request(`${api}${path}`, {
      method: 'POST',
      headers: { origin: web, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }));

  type ProxyOptions = PublicKeyCredentialRequestOptionsJSON & { challengeToken: string };
  async function proxyOptions() {
    const asked = await post('/api/passkey/generate-authenticate-options', {});
    expect(asked.status, await asked.clone().text()).toBe(200);
    return await asked.json() as ProxyOptions;
  }

  describe('POST /api/passkey/generate-authenticate-options', () => {
    test('asks for user verification and keeps every other option', async () => {
      const proxied = await proxyOptions();
      const cookieRoute = await app.fetch(new Request(`${api}/api/auth/passkey/generate-authenticate-options`, { headers: { origin: web } }));
      expect(cookieRoute.status, await cookieRoute.clone().text()).toBe(200);
      const native = await cookieRoute.json() as PublicKeyCredentialRequestOptionsJSON;

      expect(proxied.userVerification).toBe('required');
      expect(typeof proxied.challengeToken).toBe('string');
      expect(proxied.challengeToken.length).toBeGreaterThan(0);
      expect(typeof proxied.challenge).toBe('string');
      const { challengeToken: _token, challenge: _proxiedChallenge, userVerification: _proxiedUv, ...proxiedRest } = proxied;
      const { challenge: _nativeChallenge, userVerification: nativeUv, ...nativeRest } = native;
      expect(proxiedRest).toEqual(nativeRest);
      // The login page's own route keeps Better Auth's value.
      expect(nativeUv).toBe('preferred');
    });

    test('passes an upstream error body and status through and adds nothing to it', async () => {
      const original = auth.handler;
      auth.handler = async () => new Response(JSON.stringify({ error: 'upstream refused', code: 'UPSTREAM_REFUSED' }), {
        status: 429,
        headers: { 'content-type': 'application/json' },
      });
      try {
        const asked = await post('/api/passkey/generate-authenticate-options', {});
        expect(asked.status).toBe(429);
        expect(await asked.json()).toEqual({ error: 'upstream refused', code: 'UPSTREAM_REFUSED' });
      } finally {
        auth.handler = original;
      }
    });
  });

  describe('POST /api/passkey/verify-authentication', () => {
    async function verify(passkey: SoftPasskey, userVerified: boolean) {
      const { challengeToken, ...options } = await proxyOptions();
      return post('/api/passkey/verify-authentication', { response: passkey.assert(options, { userVerified }), challengeToken });
    }

    test('signs in an assertion made with user verification', async () => {
      const passkey = await passkeyOwner();
      const response = await verify(passkey, true);
      expect(response.status, await response.clone().text()).toBe(200);
      expect(typeof (await response.json() as { sessionToken: string }).sessionToken).toBe('string');
    });

    test('refuses an assertion made without user verification', async () => {
      const passkey = await passkeyOwner();
      const response = await verify(passkey, false);
      expect(response.status, await response.clone().text()).toBe(400);
      expect(await response.json()).not.toHaveProperty('sessionToken');
    });
  });
}
