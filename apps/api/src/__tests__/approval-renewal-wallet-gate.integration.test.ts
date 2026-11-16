import { expect, test } from 'bun:test';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';
import { signerFromJwk, parseApprovalRequest } from '@tinycloud/share-envelope/links';
import { Wallet } from 'ethers';
import { z } from 'zod';

// TC-3088: while a lease an external wallet signed can't be stopped by the operator kill, leases are made only for
// OpenKey-held keys. A fresh process keeps the app's auth/database singletons on the isolated child environment.
if (!process.env.TC3088_WALLET_GATE_CHILD) {
  test('renewal leases are made only for OpenKey-held keys; a wallet account asking for one is approved finite', async () => {
    const directory = await mkdtemp('/var/tmp/TC3088-wallet-gate-');
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: resolve(import.meta.dir, '../../../..'),
        env: { ...process.env, TC3088_WALLET_GATE_CHILD: directory, HOME: directory, TMPDIR: directory,
          BUN_INSTALL_CACHE_DIR: join(directory, 'bun-cache'), NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: 'http://localhost:3325', BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
          WEBAUTHN_ORIGIN: 'http://localhost:5178', WEBAUTHN_RP_ID: 'localhost', CORS_ORIGIN: 'http://localhost:5178',
          OPENKEY_RENEWAL_LEASES: 'enabled', TINYCLOUD_BOOTSTRAP_ON_SIGN: 'off',
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
  test('a wallet account is approved finite when it asks for renewal, and an OpenKey-held key is still offered a lease', async () => {
    const directory = process.env.TC3088_WALLET_GATE_CHILD!;
    const root = resolve(import.meta.dir, '../../../..');
    const database = new PGlite(join(directory, 'db'));
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    await database.close();
    const { createPrismaClient } = await import('@openkey/db');
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
    const { createPrismaApprovalRequestStore } = await import('../services/approval-request-store');
    const { auth } = await import('../auth');
    const app = (await import('../index')).default;
    const prisma = createPrismaClient();
    const authContext = await auth.$context;
    const apiOrigin = process.env.BETTER_AUTH_URL!;

    async function account(kind: 'MANAGED' | 'EXTERNAL') {
      const userId = randomUUID();
      await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, emailVerified: true } });
      const external = Wallet.createRandom();
      const privateKey = kind === 'MANAGED' ? generatePrivateKey() : external.privateKey;
      const address = kind === 'MANAGED' ? getAddressFromPrivateKey(privateKey) : external.address;
      const sealingContext = randomBytes(32).toString('base64url');
      const key = await prisma.ethereumKey.create({ data: kind === 'MANAGED'
        ? { userId, address, publicKey: '0x1', sealedBlob: await seal(privateKey, await createTeeClient().deriveKey(`openkey/key/${sealingContext}`)), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true }
        : { userId, address, publicKey: '0x1', keyType: 'EXTERNAL', isCanonicalTinyCloud: true } });
      const token = randomBytes(32).toString('base64url');
      await prisma.session.create({ data: { id: randomUUID(), userId, token, expiresAt: new Date(Date.now() + 3600_000) } });
      const cookie = (await serializeSignedCookie(authContext.authCookies.sessionToken.name, token, authContext.secret)).split(';')[0]!;
      return { key, cookie, privateKey };
    }

    const pair = generateKeyPairSync('ed25519');
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const signer = signerFromJwk(pair.privateKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string; d: string });
    const relayPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const relayJwk = await crypto.subtle.exportKey('jwk', relayPair.publicKey);
    const targetJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: jwk.x! };
    const permissions = [{ service: 'tinycloud.kv', space: 'synthetic-proof', path: 'notes', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] }, { service: 'tinycloud.capabilities', space: 'synthetic-proof', path: '', actions: ['tinycloud.capabilities/read'] }];
    let requestCount = 0;
    async function registerRequest() {
      const id = `abcdefghijklmnopqrstuvwx${'abcdefg'[requestCount++]}y`;
      const request = parseApprovalRequest({ issuer: signer.did, requestVersion: 1, targetDid: signer.did, targetPublicJwk: targetJwk, nodeOrigin: 'https://node.example.test', permissions, grantLifetimeSeconds: 3600,
        renewal: { version: 1, leaseLifetimeSeconds: 3600 }, resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x, y: relayJwk.y } }, { issuer: signer.did });
      await createPrismaApprovalRequestStore(prisma).register({ id, bodyCid: `body-${id}`, issuer: signer.did, request, expiresAt: new Date(Date.now() + 3600_000), createdAt: new Date(), resultRef: null, encryptedResult: null, resultExpiresAt: null });
      return { id, request };
    }
    const post = (path: string, body: unknown, cookie: string) => app.fetch(new Request(apiOrigin + path, {
      method: 'POST', headers: { 'content-type': 'application/json', origin: process.env.WEBAUTHN_ORIGIN!, cookie }, body: JSON.stringify(body) }));
    const prepareBody = (keyId: string, id: string, host: string, renewal?: unknown) =>
      ({ keyId, jwk: targetJwk, host, permissions, expiry: '3600s', approvalRequestId: id, ...(renewal === undefined ? {} : { renewal }) });
    const leased = { choice: 'leased', leaseLifetimeSeconds: 3600 };

    // A wallet account: a leased choice is bound as a finite one (the approval goes ahead without a lease); finite is unaffected.
    const wallet = await account('EXTERNAL');
    const walletRequest = await registerRequest();
    const leasedWalletPrepare = await post('/api/delegate/prepare', prepareBody(wallet.key.id, walletRequest.id, walletRequest.request.nodeOrigin, leased), wallet.cookie);
    expect(leasedWalletPrepare.status, await leasedWalletPrepare.clone().text()).toBe(200);
    const finiteRequest = await registerRequest();
    const finite = await post('/api/delegate/prepare', prepareBody(wallet.key.id, finiteRequest.id, finiteRequest.request.nodeOrigin, { choice: 'finite' }), wallet.cookie);
    expect(finite.status, await finite.clone().text()).toBe(200);

    // An OpenKey-held key: the leased preview is offered.
    const managed = await account('MANAGED');
    const managedRequest = await registerRequest();
    const offered = await post('/api/delegate/prepare', prepareBody(managed.key.id, managedRequest.id, managedRequest.request.nodeOrigin, leased), managed.cookie);
    expect(offered.status, await offered.clone().text()).toBe(200);
    const prepared = z.object({
      prepared: z.object({ siwe: z.string() }).passthrough(),
      authorizationContext: z.object({ token: z.string() }),
      selectedActionKeys: z.array(z.string()),
    }).parse(await offered.json());

    // The wallet completion path never carries a lease: a leased context (a managed key's) is refused there, even with a valid signature.
    const approval = { ...prepareBody(managed.key.id, managedRequest.id, managedRequest.request.nodeOrigin, leased), protocolVersion: 1, prepared: prepared.prepared,
      authorizationContextToken: prepared.authorizationContext.token, selectedActionIds: prepared.selectedActionKeys };
    const signature = await new Wallet(managed.privateKey.startsWith('0x') ? managed.privateKey : `0x${managed.privateKey}`).signMessage(prepared.prepared.siwe);
    const complete = await post('/api/delegate/complete', { ...approval, signature }, managed.cookie);
    expect(complete.status).toBe(400);
    expect(await complete.json()).toMatchObject({ code: 'renewal_external_wallet' });
    expect((await prisma.approvalRequest.findUniqueOrThrow({ where: { id: managedRequest.id } })).resultRef).toBeNull();

    // The wallet owner approves through /complete repeating the tick: the approval goes ahead, finite, with no lease.
    const walletPrepared = z.object({
      prepared: z.object({ siwe: z.string() }).passthrough(),
      authorizationContext: z.object({ token: z.string() }),
      selectedActionKeys: z.array(z.string()),
    }).parse(await leasedWalletPrepare.json());
    const walletApproval = { ...prepareBody(wallet.key.id, walletRequest.id, walletRequest.request.nodeOrigin, leased), protocolVersion: 1, prepared: walletPrepared.prepared,
      authorizationContextToken: walletPrepared.authorizationContext.token, selectedActionIds: walletPrepared.selectedActionKeys };
    const walletSignature = await new Wallet(wallet.privateKey).signMessage(walletPrepared.prepared.siwe);
    const approved = await post('/api/delegate/complete', { ...walletApproval, signature: walletSignature }, wallet.cookie);
    expect(approved.status, await approved.clone().text()).toBe(200);
    expect((await prisma.approvalRequest.findUniqueOrThrow({ where: { id: walletRequest.id } })).resultRef).not.toBeNull();
    expect(await prisma.renewalLease.count()).toBe(0);
    expect(JSON.stringify(await approved.json())).not.toContain('leaseAuthorization');
    await prisma.$disconnect();
  }, 120_000);
}
