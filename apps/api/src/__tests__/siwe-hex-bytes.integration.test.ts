// TC-3826: `/api/keys/:id/sign` reads `0x` hex the way the signer covers it.
// A sign-in message behind a BOM, or with a byte that is not UTF-8, is refused
// (400, nothing signed); binary bytes that hold no sign-in message still sign.
import { expect, test } from 'bun:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';

// A fresh process avoids Bun's process-wide route/auth mocks in the unit lane.
if (!process.env.TC_SIWE_HEX_CHILD) {
  test('/keys/:id/sign refuses a hex SIWE behind a BOM or with a non-UTF-8 byte, and signs binary bytes', async () => {
    const directory = await mkdtemp('/var/tmp/openkey-siwe-hex-');
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: resolve(import.meta.dir, '../../../..'),
        env: { ...process.env, TC_SIWE_HEX_CHILD: directory, HOME: directory, TMPDIR: directory,
          BUN_INSTALL_CACHE_DIR: join(directory, 'bun-cache'), NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: 'http://localhost:3324', BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
          WEBAUTHN_ORIGIN: 'https://openkey.example', WEBAUTHN_RP_ID: 'localhost', CORS_ORIGIN: 'https://openkey.example',
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
  test('BOM and non-UTF-8 SIWE hex are refused with 400; binary hex signs', async () => {
    const directory = process.env.TC_SIWE_HEX_CHILD!;
    const root = resolve(import.meta.dir, '../../../..');
    const database = new PGlite(join(directory, 'db'));
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    await database.close();
    // The app's auth/database/TEE singletons must capture the isolated child
    // environment only after its tracked schema exists, not at static import.
    const { createPrismaClient } = await import('@openkey/db');
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
    const { auth } = await import('../auth');
    const app = (await import('../index')).default;
    const prisma = createPrismaClient();
    const userId = randomUUID();
    const user = await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, emailVerified: true } });
    const privateKey = generatePrivateKey();
    const address = getAddressFromPrivateKey(privateKey);
    const sealingContext = randomBytes(32).toString('base64url');
    const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    const key = await prisma.ethereumKey.create({ data: { userId: user.id, address, publicKey: '0x1', sealedBlob: await seal(privateKey, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
    const token = randomBytes(32).toString('base64url');
    await prisma.session.create({ data: { id: randomUUID(), userId, token, expiresAt: new Date(Date.now() + 3600_000) } });
    const authContext = await auth.$context;
    const cookie = (await serializeSignedCookie(authContext.authCookies.sessionToken.name, token, authContext.secret)).split(';')[0]!;
    const OPENKEY = 'https://openkey.example';

    const now = Date.now();
    const siwe = [
      'openkey.example wants you to sign in with your Ethereum account:',
      address,
      '',
      'Sign in to OpenKey.',
      '',
      `URI: ${OPENKEY}`,
      'Version: 1',
      'Chain ID: 1',
      'Nonce: abcdef12345678',
      `Issued At: ${new Date(now).toISOString()}`,
      `Expiration Time: ${new Date(now + 3600_000).toISOString()}`,
    ].join('\n');
    const bytes = (value: Uint8Array) => `0x${Buffer.from(value).toString('hex')}`;
    const utf8 = (text: string) => new TextEncoder().encode(text);
    const sign = (message: string, format?: 'raw') => app.fetch(new Request(`${process.env.BETTER_AUTH_URL}/api/keys/${key.id}/sign`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie, origin: OPENKEY },
      body: JSON.stringify({ message, ...(format ? { format } : {}), requestOrigin: OPENKEY }),
    }));

    const bom = bytes(new Uint8Array([0xef, 0xbb, 0xbf, ...utf8(siwe)]));
    const statementAt = siwe.indexOf('Sign in');
    const invalidByte = bytes(new Uint8Array([...utf8(siwe.slice(0, statementAt)), 0xff, ...utf8(siwe.slice(statementAt))]));
    for (const [name, message] of [['a BOM before the SIWE', bom], ['a non-UTF-8 byte in the statement', invalidByte]] as const) {
      for (const format of ['raw', undefined] as const) {
        const response = await sign(message, format);
        const text = await response.text();
        expect(response.status, `${name} (${format ?? 'personal'}): ${text}`).toBe(400);
        const body = JSON.parse(text);
        expect(body.code, `${name} (${format ?? 'personal'})`).toBe('invalid_siwe_message');
        expect(body.signature, `${name} (${format ?? 'personal'})`).toBeUndefined();
      }
    }

    // The same SIWE as clean UTF-8 hex signs, so the refusals above are the BOM and the bad byte.
    const clean = await sign(bytes(utf8(siwe)), 'raw');
    const cleanText = await clean.text();
    expect(clean.status, cleanText).toBe(200);
    expect(JSON.parse(cleanText).signature).toMatch(/^0x[0-9a-f]{130}$/);

    // Binary bytes that are not UTF-8 and hold no sign-in message still sign, as raw and as personal hex.
    const binary = new Uint8Array(32);
    for (let i = 0; i < binary.length; i++) binary[i] = (i * 37 + 0x80) & 0xff;
    binary[0] = 0xff;
    expect(() => new TextDecoder('utf-8', { fatal: true }).decode(binary)).toThrow();
    for (const format of ['raw', undefined] as const) {
      const response = await sign(bytes(binary), format);
      const text = await response.text();
      expect(response.status, `binary (${format ?? 'personal'}): ${text}`).toBe(200);
      expect(JSON.parse(text).signature).toMatch(/^0x[0-9a-f]{130}$/);
    }
  }, 60_000);
}
