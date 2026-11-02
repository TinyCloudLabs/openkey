import { expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';
import { signerFromJwk, prepareLinkRecord, openLinkRecord, parseApprovalRequest } from '@tinycloud/share-envelope/links';
import { z } from 'zod';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';

// A fresh process avoids Bun's process-wide route/auth mocks in the unit lane.
if (!process.env.TC2212_APPROVAL_API_CHILD) {
  test('a signed approval request may sign a year, and suggest a shorter default; the owner picks up to the signed maximum', async () => {
    const directory = await mkdtemp('/var/tmp/TC2274-openkey-api-');
    console.log(`TC2274 private integration directory: ${directory}`);
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
  test('a year-long signed maximum is not clamped to 30 days and is still a ceiling', async () => {
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
    const permissions = [{ service: 'tinycloud.kv', space: 'synthetic-proof', path: 'notes', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] }, { service: 'tinycloud.capabilities', space: 'synthetic-proof', path: '', actions: ['tinycloud.capabilities/read'] }];
    const request = parseApprovalRequest({ issuer: signer.did, requestVersion: 1, targetDid: signer.did, targetPublicJwk: targetJwk, nodeOrigin: 'https://node.example.test', permissions, grantLifetimeSeconds: 31_536_000, suggestedLifetimeSeconds: 604_800, resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x, y: relayJwk.y } });
    const sealed = await prepareLinkRecord({ type: 'openkey-approval-request', issuerKey: signer, apiOrigin: 'https://api.tinycloud.xyz', expiresAt: new Date(Date.now() + 3600_000), plaintext: new TextEncoder().encode(JSON.stringify(request)) });
    const opened = await openLinkRecord(sealed.record, sealed.key);
    const id = 'abcdefghijklmnopqrstuvwxyz';
    const apiOrigin = process.env.BETTER_AUTH_URL!;
    const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');
    async function post(path: string, body: unknown, headers: Record<string, string> = {}) {
      return app.fetch(new Request(apiOrigin + path, { method: 'POST', headers: { 'content-type': 'application/json', origin: process.env.WEBAUTHN_ORIGIN!, ...headers }, body: JSON.stringify(body) }));
    }
    await createPrismaApprovalRequestStore(prisma).register({ id, bodyCid: opened.header.bodyCid, issuer: opened.header.issuer, request: parseApprovalRequest(opened.value, { issuer: opened.header.issuer }), expiresAt: new Date(opened.header.expiresAt), createdAt: new Date(), resultRef: null, encryptedResult: null, resultExpiresAt: null });
    const body = { keyId: ownerKey.id, jwk: targetJwk, host: request.nodeOrigin, permissions, expiry: '604800s', approvalRequestId: id };
    const prepareAs = (overrides: Record<string, unknown>) => post('/api/delegate/prepare', { ...body, ...overrides }, { cookie });
    const expiryOf = (siwe: string) => Date.parse(/^Expiration Time: (.+)$/m.exec(siwe)![1]!);
    // The signed request carries the suggestion; the schema keeps it between a second and the maximum.
    expect(request.suggestedLifetimeSeconds).toBe(604_800);
    const base = { issuer: signer.did, requestVersion: 1, targetDid: signer.did, targetPublicJwk: targetJwk, nodeOrigin: request.nodeOrigin, permissions, grantLifetimeSeconds: 3600, resultEncryptionPublicJwk: request.resultEncryptionPublicJwk };
    expect(() => parseApprovalRequest({ ...base, suggestedLifetimeSeconds: 3601 })).toThrow();
    expect(() => parseApprovalRequest({ ...base, suggestedLifetimeSeconds: 0 })).toThrow();
    expect(() => parseApprovalRequest({ ...base, suggestedLifetimeSeconds: 3600 })).not.toThrow();
    // The signed maximum is not clamped to the 30-day link ceiling, and it stays the ceiling.
    const year = await prepareAs({ expiry: '31536000s' });
    expect(year.status, await year.clone().text()).toBe(200);
    const yearSiwe = z.object({ prepared: z.object({ siwe: z.string() }).passthrough() }).parse(await year.json()).prepared.siwe;
    expect(expiryOf(yearSiwe) - Date.now()).toBeGreaterThan(365 * 86_400_000 - 60_000);
    expect((await prepareAs({ expiry: '31536001s' })).status).toBe(400);
    expect((await prepareAs({ expiry: '31536001s', expiryChosen: true })).status).toBe(400);
    // The suggested default prepares, signs and saves as itself.
    const preparedResponse = await prepareAs({});
    expect(preparedResponse.status, await preparedResponse.clone().text()).toBe(200);
    const prepared = z.object({
      prepared: z.object({ siwe: z.string() }).passthrough(),
      authorizationContext: z.object({ token: z.string() }),
      selectedActionKeys: z.array(z.string()),
    }).parse(await preparedResponse.json());
    expect(expiryOf(prepared.prepared.siwe) - Date.now()).toBeLessThanOrEqual(604_800_000);
    expect(expiryOf(prepared.prepared.siwe) - Date.now()).toBeGreaterThan(604_800_000 - 60_000);
    const approval = { ...body, protocolVersion: 1, prepared: prepared.prepared, authorizationContextToken: prepared.authorizationContext.token, selectedActionIds: prepared.selectedActionKeys };
    const approvedResponse = await post('/api/delegate', approval, { cookie });
    expect(approvedResponse.status, await approvedResponse.clone().text()).toBe(200);
    const saved = await prisma.approvalRequest.findUniqueOrThrow({ where: { id } });
    expect(saved.delegationExpiresAt!.getTime()).toBe(expiryOf(prepared.prepared.siwe));
  });
}
