// TC-3826: a SIWE whose statement hides a fake `Expiration Time:` line behind
// `\r`, U+2028 or U+2029 is refused on every route that signs one, before any
// key is unsealed; a normal SIWE still signs.
import { expect, test } from 'bun:test';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';

// A fresh process avoids Bun's process-wide route/auth mocks in the unit lane.
if (!process.env.TC_SIWE_FORBIDDEN_CHILD) {
  test('routes that sign a SIWE refuse one with a forbidden character', async () => {
    const directory = await mkdtemp('/var/tmp/openkey-siwe-forbidden-');
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: resolve(import.meta.dir, '../../../..'),
        env: { ...process.env, TC_SIWE_FORBIDDEN_CHILD: directory, HOME: directory, TMPDIR: directory,
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
  test('sign, authorize-sign-prepare, complete and the managed POST refuse; a normal SIWE signs', async () => {
    const directory = process.env.TC_SIWE_FORBIDDEN_CHILD!;
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
    const headers = { cookie, origin: OPENKEY };
    const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
    const host = 'https://node.tinycloud.xyz';

    const now = Date.now();
    const fake = new Date(now + 86_400_000).toISOString();
    const real = new Date(now + 10 * 365 * 86_400_000).toISOString();
    function siwe(statementPrefix: string): string {
      return [
        'openkey.example wants you to sign in with your Ethereum account:',
        address,
        '',
        `${statementPrefix}I further authorize the stated URI to perform the following actions on my behalf: (1) 'kv': 'get' for 'tinycloud:pkh:eip155:1:${address}:default/kv'.`,
        '',
        `URI: ${OPENKEY}`,
        'Version: 1',
        'Chain ID: 1',
        'Nonce: abcdef12345678',
        `Issued At: ${new Date(now).toISOString()}`,
        `Expiration Time: ${real}`,
      ].join('\n');
    }
    const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;
    const post = (path: string, body: unknown) => app.fetch(new Request(`${process.env.BETTER_AUTH_URL}${path}`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
    }));
    async function expectRefused(response: Response, label: string) {
      const text = await response.text();
      expect(response.status, `${label}: ${text}`).toBe(400);
      expect(JSON.parse(text).code, `${label}: ${text}`).toBe('invalid_siwe_message');
    }

    for (const [name, separator] of [['CR', '\r'], ['U+2028', '\u2028'], ['U+2029', '\u2029']] as const) {
      const attack = siwe(`Expiration Time: ${fake}${separator} `);
      await expectRefused(await post(`/api/keys/${key.id}/sign`, { message: attack, requestOrigin: OPENKEY }), `${name} /sign text`);
      await expectRefused(await post(`/api/keys/${key.id}/sign`, { message: hex(attack), format: 'raw', requestOrigin: OPENKEY }), `${name} /sign raw hex`);
      await expectRefused(await post(`/api/keys/${key.id}/sign`, { message: hex(attack), requestOrigin: OPENKEY }), `${name} /sign personal hex`);
      await expectRefused(await post('/api/delegate/authorize-sign-prepare', { keyId: key.id, siwe: attack, jwk, host, requestOrigin: OPENKEY }), `${name} /authorize-sign-prepare`);
      await expectRefused(await post('/api/delegate/complete', { prepared: { siwe: attack }, signature: '0x00', host, jwk }), `${name} /complete`);
      await expectRefused(await post('/api/delegate', { keyId: key.id, jwk, host, prepared: { siwe: attack } }), `${name} managed POST`);
    }

    // The same text with no line separator is an ordinary statement: it signs.
    const normal = await post(`/api/keys/${key.id}/sign`, { message: siwe(`Expiration Time: ${fake} `), requestOrigin: OPENKEY });
    const normalText = await normal.text();
    expect(normal.status, normalText).toBe(200);
    expect(JSON.parse(normalText).signature).toMatch(/^0x[0-9a-f]{130}$/);
    // Text that is not a sign-in keeps its bytes, control characters included.
    const plain = await post(`/api/keys/${key.id}/sign`, { message: 'hello\r\nworld' });
    expect(plain.status, await plain.clone().text()).toBe(200);
  }, 60_000);
}
