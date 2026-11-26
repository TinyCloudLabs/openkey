// TC-3844: `/api/keys/:id/sign` logs one `siwe_signed` line per sign-in message it signs: the route, whether it had an
// Expiration Time, whether it carries a ReCap and the app origin. Never the message, address, nonce, key or user;
// nothing for a message that is not a sign-in.
import { expect, test } from 'bun:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';

// A fresh process avoids Bun's process-wide route/auth mocks in the unit lane.
if (!process.env.TC_SIWE_SIGNED_EVENT_CHILD) {
  test('/keys/:id/sign logs whether a signed sign-in message had an expiry, and nothing else about it', async () => {
    const directory = await mkdtemp('/var/tmp/openkey-siwe-signed-event-');
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: resolve(import.meta.dir, '../../../..'),
        env: { ...process.env, TC_SIWE_SIGNED_EVENT_CHILD: directory, HOME: directory, TMPDIR: directory,
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
  test('siwe_signed carries route, siwe_expiry, recap and origin only', async () => {
    const directory = process.env.TC_SIWE_SIGNED_EVENT_CHILD!;
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
    const NONCE = 'zq81noncevalue27';
    const resource = `tinycloud:pkh:eip155:1:${address}:default/kv/data`;
    const recap = `urn:recap:${Buffer.from(JSON.stringify({
      att: { [resource]: { 'tinycloud.kv/get': [{}] } },
      prf: [],
    })).toString('base64url')}`;
    // The statement a ReCap SIWE carries; the recap parser refuses a ReCap whose statement does not list it.
    const recapStatement = `I further authorize the stated URI to perform the following actions on my behalf: (1) 'tinycloud.kv': 'get' for '${resource}'.`;
    const siwe = ({ expiry, withRecap }: { expiry: boolean; withRecap: boolean }) => [
      'openkey.example wants you to sign in with your Ethereum account:',
      address,
      '',
      withRecap ? recapStatement : 'Sign in to OpenKey.',
      '',
      `URI: ${OPENKEY}`,
      'Version: 1',
      'Chain ID: 1',
      `Nonce: ${NONCE}`,
      `Issued At: ${new Date(now).toISOString()}`,
      ...(expiry ? [`Expiration Time: ${new Date(now + 3600_000).toISOString()}`] : []),
      ...(withRecap ? ['Resources:', `- ${recap}`] : []),
    ].join('\n');
    const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;
    const sign = (message: string, format?: 'raw') => app.fetch(new Request(`${process.env.BETTER_AUTH_URL}/api/keys/${key.id}/sign`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie, origin: OPENKEY },
      body: JSON.stringify({ message, ...(format ? { format } : {}), requestOrigin: OPENKEY }),
    }));

    const original = process.stdout.write.bind(process.stdout);
    const lines: string[] = [];
    process.stdout.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
      lines.push(...(typeof chunk === 'string' ? chunk : new TextDecoder().decode(chunk)).split('\n').filter((line) => line.startsWith('{')));
      return (original as (...args: unknown[]) => boolean)(chunk, ...rest);
    }) as typeof process.stdout.write;
    const signedEvents = async (message: string, format?: 'raw') => {
      const before = lines.length;
      const response = await sign(message, format);
      const text = await response.text();
      expect(response.status, text).toBe(200);
      return lines.slice(before).filter((line) => line.includes('"siwe_signed"'));
    };
    const fieldsOf = (line: string) => {
      const { ts: _ts, request_id: _requestId, ...fields } = JSON.parse(line);
      return fields;
    };
    const expected = (expiry: 'present' | 'absent', withRecap: boolean) => ({
      level: 'info', event: 'siwe_signed', route: '/api/keys/:keyId/sign', siwe_expiry: expiry, recap: withRecap, claimed_origin: OPENKEY,
    });

    try {
      const cases = [
        [siwe({ expiry: false, withRecap: false }), undefined, expected('absent', false)],
        [siwe({ expiry: true, withRecap: false }), undefined, expected('present', false)],
        [hex(siwe({ expiry: true, withRecap: true })), 'raw', expected('present', true)],
        [hex(siwe({ expiry: true, withRecap: true })), undefined, expected('present', true)],
      ] as const;
      for (const [message, format, fields] of cases) {
        const events = await signedEvents(message, format);
        expect(events.length, `${format ?? 'personal'}: ${message.slice(0, 40)}`).toBe(1);
        expect(fieldsOf(events[0]!)).toEqual(fields);
        for (const secret of [address, address.toLowerCase(), userId, key.id, NONCE, 'Sign in to OpenKey']) {
          expect(events[0]).not.toContain(secret);
        }
      }
      // A message that is not a sign-in is signed with no event.
      expect(await signedEvents('Please sign this receipt: order #4472')).toEqual([]);
    } finally {
      process.stdout.write = original;
    }
  }, 60_000);
}
