import { expect, test } from 'bun:test';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';
import { signerFromJwk, prepareLinkRecord, openLinkRecord, parseApprovalRequest } from '@tinycloud/share-envelope/links';
import { z } from 'zod';

// A fresh process avoids Bun's process-wide route/auth mocks in the unit lane.
if (!process.env.TC2212_APPROVAL_API_CHILD) {
  test('the signed approval page for access that can open all encrypted data signs the length the owner picks', async () => {
    const directory = await mkdtemp('/var/tmp/TC4156-openkey-api-');
    console.log(`TC4156 private integration directory: ${directory}`);
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: resolve(import.meta.dir, '../../../..'),
        env: { ...process.env, TC2212_APPROVAL_API_CHILD: directory, HOME: directory, TMPDIR: directory,
          BUN_INSTALL_CACHE_DIR: join(directory, 'bun-cache'), NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: 'http://localhost:3324', BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
          WEBAUTHN_ORIGIN: 'http://localhost:5178', WEBAUTHN_RP_ID: 'localhost', CORS_ORIGIN: 'http://localhost:5178',
          APPROVAL_RESULT_RETENTION_SECONDS: '600', TINYCLOUD_BOOTSTRAP_ON_SIGN: 'off',
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
  test('the signed length is the 1 hour default, the picked length, or the 7 day limit', async () => {
    const directory = process.env.TC2212_APPROVAL_API_CHILD!;
    const root = resolve(import.meta.dir, '../../../..');
    const database = new PGlite(join(directory, 'db'));
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    await database.close();
    // The app's auth/database/TEE singletons must capture the isolated child
    // environment only after its tracked schema exists, not at static import.
    const { createPrismaClient } = await import('@openkey/db');
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
    const { createPrismaApprovalRequestStore } = await import('../services/approval-request-store');
    const { auth } = await import('../auth');
    const app = (await import('../index')).default;
    const prisma = createPrismaClient();
    const userId = randomUUID();
    const user = await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, emailVerified: true } });
    const privateKey = generatePrivateKey();
    const address = getAddressFromPrivateKey(privateKey);
    const sealingContext = randomBytes(32).toString('base64url');
    const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    const ownerKey = await prisma.ethereumKey.create({ data: { userId: user.id, address, publicKey: '0x1', sealedBlob: await seal(privateKey, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
    const token = randomBytes(32).toString('base64url');
    await prisma.session.create({ data: { id: randomUUID(), userId, token, expiresAt: new Date(Date.now() + 3600_000) } });
    const authContext = await auth.$context;
    const cookie = (await serializeSignedCookie(authContext.authCookies.sessionToken.name, token, authContext.secret)).split(';')[0]!;
    const pair = generateKeyPairSync('ed25519');
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const signer = signerFromJwk(pair.privateKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string; d: string });
    const relayPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const relayJwk = await crypto.subtle.exportKey('jwk', relayPair.publicKey);
    const targetJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: jwk.x! };
    const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default`;
    const permissions = [{ service: 'tinycloud.encryption', space: 'encryption', path: network, actions: ['tinycloud.encryption/decrypt'] }];
    const requestOf = (grantLifetimeSeconds: number) => parseApprovalRequest({ issuer: signer.did, requestVersion: 1, targetDid: signer.did, targetPublicJwk: targetJwk, nodeOrigin: 'https://node.example.test', permissions, grantLifetimeSeconds, resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x, y: relayJwk.y } });
    const asked30 = requestOf(30 * 86_400);
    const sealed = await prepareLinkRecord({ type: 'openkey-approval-request', issuerKey: signer, apiOrigin: 'https://api.tinycloud.xyz', expiresAt: new Date(Date.now() + 3600_000), plaintext: new TextEncoder().encode(JSON.stringify(asked30)) });
    const opened = await openLinkRecord(sealed.record, sealed.key);
    const apiOrigin = process.env.BETTER_AUTH_URL!;
    async function post(path: string, body: unknown, headers: Record<string, string> = {}) {
      return app.fetch(new Request(apiOrigin + path, { method: 'POST', headers: { 'content-type': 'application/json', origin: process.env.WEBAUTHN_ORIGIN!, ...headers }, body: JSON.stringify(body) }));
    }
    const ids = { asked30: 'abcdefghijklmnopqrstuvwxyz', asked3: 'bcdefghijklmnopqrstuvwxyza' };
    for (const [key, id] of Object.entries(ids)) {
      await createPrismaApprovalRequestStore(prisma).register({ id, bodyCid: opened.header.bodyCid, issuer: opened.header.issuer, request: key === 'asked30' ? asked30 : requestOf(3 * 86_400), expiresAt: new Date(opened.header.expiresAt), createdAt: new Date(), resultRef: null, encryptedResult: null, resultExpiresAt: null });
    }
    const body = { keyId: ownerKey.id, jwk: targetJwk, host: asked30.nodeOrigin, permissions, approvalRequestId: ids.asked30 };
    const prepareAs = (overrides: Record<string, unknown>) => post('/api/delegate/prepare', { ...body, ...overrides }, { cookie });
    const expiryOf = (siwe: string) => Date.parse(/^Expiration Time: (.+)$/m.exec(siwe)![1]!);
    const issuedAtOf = (siwe: string) => Date.parse(/^Issued At: (.+)$/m.exec(siwe)![1]!);
    const prepare = async (overrides: Record<string, unknown>) => {
      const response = await prepareAs(overrides);
      expect(response.status, await response.clone().text()).toBe(200);
      return z.object({
        prepared: z.object({ siwe: z.string() }).passthrough(),
        authorizationContext: z.object({ token: z.string() }),
        selectedActionKeys: z.array(z.string()),
      }).parse(await response.json());
    };
    const signedMs = (prepared: { prepared: { siwe: string } }) => expiryOf(prepared.prepared.siwe) - issuedAtOf(prepared.prepared.siwe);
    const near = (actualMs: number, expectedMs: number) => expect(Math.abs(actualMs - expectedMs)).toBeLessThanOrEqual(5_000);
    const HOUR = 3_600_000;
    const DAY = 24 * HOUR;
    // The page starts a once-tier request at one hour and sends that length: one hour is what is signed.
    near(signedMs(await prepare({ expiry: '3600s' })), HOUR);
    // The owner's explicit pick below the request is signed as picked, with or without the pick flag.
    near(signedMs(await prepare({ expiry: '259200s', expiryChosen: true })), 3 * DAY);
    near(signedMs(await prepare({ expiry: '259200s' })), 3 * DAY);
    // The longest allowed on all encrypted data is 7 days, and a longer one is refused even when the request asked 30.
    near(signedMs(await prepare({ expiry: '604800s', expiryChosen: true })), 7 * DAY);
    const overLimit = await prepareAs({ expiry: '2592000s', expiryChosen: true });
    expect(overLimit.status).toBe(400);
    expect(await overLimit.json()).toMatchObject({ code: 'request_binding' });
    // A request that asked 3 days signs exactly 3 days when the owner picks the longer length.
    near(signedMs(await prepare({ approvalRequestId: ids.asked3, expiry: '259200s', expiryChosen: true })), 3 * DAY);
  }, 30_000);
}
