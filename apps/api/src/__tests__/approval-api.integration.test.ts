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
  test('real authenticated approval, encrypted fetch retries and durable ACK on tracked schema', async () => {
    const directory = await mkdtemp('/var/tmp/TC2212-openkey-api-');
    console.log(`TC2212 private integration directory: ${directory}`);
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
  test('actual owner consent pipeline and requester-bound result lifecycle', async () => {
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
    const request = parseApprovalRequest({ issuer: signer.did, requestVersion: 1, targetDid: signer.did, targetPublicJwk: targetJwk, nodeOrigin: 'https://node.example.test', permissions, grantLifetimeSeconds: 3600, resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x, y: relayJwk.y } });
    const sealed = await prepareLinkRecord({ type: 'openkey-approval-request', issuerKey: signer, apiOrigin: 'https://api.tinycloud.xyz', expiresAt: new Date(Date.now() + 3600_000), plaintext: new TextEncoder().encode(JSON.stringify(request)) });
    const opened = await openLinkRecord(sealed.record, sealed.key);
    const id = 'abcdefghijklmnopqrstuvwxyz';
    const apiOrigin = process.env.BETTER_AUTH_URL!;
    const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');
    async function post(path: string, body: unknown, headers: Record<string, string> = {}) {
      return app.fetch(new Request(apiOrigin + path, { method: 'POST', headers: { 'content-type': 'application/json', origin: process.env.WEBAUTHN_ORIGIN!, ...headers }, body: JSON.stringify(body) }));
    }
    const initialResultPath = `/api/approval-requests/${id}/result`;
    const signedReference = { bodyCid: opened.header.bodyCid, header: opened.header, signature: opened.signature };
    const pending = await post(initialResultPath, signedReference, { 'OpenKey-Session-Proof': proof('discover', initialResultPath) });
    expect(pending.status).toBe(202);
    expect(await pending.json()).toEqual({ status: 'pending' });
    expect((await post(initialResultPath, signedReference, { 'OpenKey-Session-Proof': proof('discover', initialResultPath) })).status).toBe(202);
    expect((await post(initialResultPath, signedReference, { 'OpenKey-Session-Proof': proof('discover', initialResultPath, '', '', generateKeyPairSync('ed25519').privateKey) })).status).toBe(401);
    expect((await post(initialResultPath, signedReference, { 'OpenKey-Session-Proof': proof('fetch', initialResultPath) })).status).toBe(401);
    expect((await post(initialResultPath, { ...signedReference, bodyCid: 'wrong-sealed-cid' }, { 'OpenKey-Session-Proof': proof('discover', initialResultPath) })).status).toBe(400);
    expect((await post(initialResultPath, { ...signedReference, signature: { algorithm: 'Ed25519', value: Buffer.alloc(64).toString('base64url') } }, { 'OpenKey-Session-Proof': proof('discover', initialResultPath) })).status).toBe(400);
    expect(await prisma.approvalRequest.findUnique({ where: { id } })).toBeNull();
    await createPrismaApprovalRequestStore(prisma).register({ id, bodyCid: opened.header.bodyCid, issuer: opened.header.issuer, request: parseApprovalRequest(opened.value, { issuer: opened.header.issuer }), expiresAt: new Date(opened.header.expiresAt), createdAt: new Date(), resultRef: null, encryptedResult: null, resultExpiresAt: null });
    const body = { keyId: ownerKey.id, jwk: targetJwk, host: request.nodeOrigin, permissions, expiry: '3600s', approvalRequestId: id };
    expect((await post('/api/delegate/prepare', body)).status).toBe(401);
    const otherUserId = randomUUID();
    const otherToken = randomBytes(32).toString('base64url');
    await prisma.user.create({ data: { id: otherUserId, email: `${otherUserId}@example.test`, emailVerified: true } });
    await prisma.session.create({ data: { id: randomUUID(), userId: otherUserId, token: otherToken, expiresAt: new Date(Date.now() + 3600_000) } });
    const otherCookie = (await serializeSignedCookie(authContext.authCookies.sessionToken.name, otherToken, authContext.secret)).split(';')[0]!;
    expect((await post('/api/delegate/prepare', body, { cookie: otherCookie })).status).toBe(404);
    const otherJwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
    expect((await post('/api/delegate/prepare', { ...body, jwk: { kty: 'OKP', crv: 'Ed25519', x: otherJwk.x } }, { cookie })).status).toBe(400);
    expect((await post('/api/delegate/prepare', { ...body, permissions: [{ ...permissions[0], actions: ['tinycloud.kv/get'] }, permissions[1]] }, { cookie })).status).toBe(400);
    const preparedResponse = await post('/api/delegate/prepare', body, { cookie });
    expect(preparedResponse.status, await preparedResponse.clone().text()).toBe(200);
    const prepared = z.object({
      prepared: z.object({ siwe: z.string() }).passthrough(),
      authorizationContext: z.object({ token: z.string() }),
      selectedActionKeys: z.array(z.string()),
    }).parse(await preparedResponse.json());
    const approval = { ...body, protocolVersion: 1, prepared: prepared.prepared, authorizationContextToken: prepared.authorizationContext.token, selectedActionIds: prepared.selectedActionKeys };
    const refused = await post('/api/delegate', { ...approval, approvalRequestId: 'zyxwvutsrqponmlkjihgfedcba2' }, { cookie });
    expect(refused.status).toBe(400);
    expect((await prisma.approvalRequest.findUniqueOrThrow({ where: { id } })).resultRef).toBeNull();
    expect((await post('/api/delegate', approval, { cookie: otherCookie })).status).toBe(404);
    const wrongSignature = await Wallet.createRandom().signMessage(prepared.prepared.siwe);
    expect((await post('/api/delegate/complete', { ...approval, signature: wrongSignature }, { cookie })).status).toBe(400);
    // A preview loaded before the deadline cannot be approved after expiry.
    // Rejection must not consume the consent context.
    await prisma.approvalRequest.update({ where: { id }, data: { expiresAt: new Date(0) } });
    expect((await post('/api/delegate', approval, { cookie })).status).toBe(410);
    expect((await prisma.approvalRequest.findUniqueOrThrow({ where: { id } })).resultRef).toBeNull();
    await prisma.approvalRequest.update({ where: { id }, data: { expiresAt: new Date(opened.header.expiresAt) } });
    const approvedResponse = await post('/api/delegate', approval, { cookie });
    expect(approvedResponse.status, await approvedResponse.clone().text()).toBe(200);
    const delegation = z.object({ ownerDid: z.string(), siwe: z.string() }).passthrough().parse(await approvedResponse.json());
    const saved = await prisma.approvalRequest.findUniqueOrThrow({ where: { id } });
    expect(saved.approvedByUserId).toBe(userId);
    expect(saved.ownerDid).toBe(delegation.ownerDid);
    // Approved, unacknowledged results outlive the original request deadline.
    await prisma.approvalRequest.update({ where: { id }, data: { expiresAt: new Date(0) } });
    function proof(action: 'discover' | 'fetch' | 'ack', path: string, ref = '', ackId = '', signingKey = pair.privateKey) {
      const head = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: jkt, typ: 'openkey-session-proof+jwt' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ client_id: 'openkey-approval-result-v1', cred_hash: createHash('sha256').update(JSON.stringify([action, id, opened.header.bodyCid, ref, ackId])).digest('base64url'), htm: 'POST', htu: apiOrigin + path, iat: Math.floor(Date.now() / 1000), jti: randomBytes(24).toString('base64url') })).toString('base64url');
      return `${head}.${payload}.${sign(null, Buffer.from(`${head}.${payload}`), signingKey).toString('base64url')}`;
    }
    const resultPath = `/api/approval-requests/${id}/result`;
    const discovered = await post(resultPath, { bodyCid: saved.bodyCid }, { 'OpenKey-Session-Proof': proof('discover', resultPath) });
    expect(discovered.status).toBe(200);
    const { resultRef } = z.object({ resultRef: z.string() }).parse(await discovered.json());
    const fetchPath = `/api/approval-results/${resultRef}/fetch`;
    const binding = { requestId: id, bodyCid: saved.bodyCid };
    expect((await post(fetchPath, binding)).status).toBe(401);
    expect((await post(fetchPath, binding, { 'OpenKey-Session-Proof': proof('fetch', fetchPath, resultRef, '', generateKeyPairSync('ed25519').privateKey) })).status).toBe(401);
    expect((await post(fetchPath, { ...binding, bodyCid: 'wrong-sealed-cid' }, { 'OpenKey-Session-Proof': proof('fetch', fetchPath, resultRef) })).status).toBe(400);
    const fetched = await post(fetchPath, binding, { 'OpenKey-Session-Proof': proof('fetch', fetchPath, resultRef) });
    expect(fetched.status).toBe(200);
    const result = z.object({
      relay: z.object({
        ephemeralPublicJwk: z.object({ kty: z.literal('EC'), crv: z.literal('P-256'), x: z.string(), y: z.string() }).passthrough(),
        nonce: z.string(),
        ciphertext: z.string(),
      }).passthrough(),
    }).passthrough().parse(await fetched.json());
    expect(await (await post(fetchPath, binding, { 'OpenKey-Session-Proof': proof('fetch', fetchPath, resultRef) })).json()).toEqual(result);
    const recipient = await crypto.subtle.importKey('jwk', result.relay.ephemeralPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: recipient }, relayPair.privateKey, 256);
    const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const context = new TextEncoder().encode(id);
    const aes = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: context, info: new TextEncoder().encode('openkey-device-relay-v1') }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(result.relay.nonce, 'base64url'), additionalData: context }, aes, Buffer.from(result.relay.ciphertext, 'base64url'));
    const wrapped = JSON.parse(new TextDecoder().decode(plaintext));
    expect(wrapped).toEqual({ resultVersion: 1, requestId: id, requestDigest: saved.bodyCid, requesterDid: signer.did, targetDid: signer.did, ownerDid: delegation.ownerDid, delegationExpiresAt: new SiweMessage(delegation.siwe).expirationTime, delegation });
    // CLI verification/profile durability is exercised by the separate CLI
    // vertical smoke. This API proof deliberately makes no commitLogin claim.
    const ackPath = `/api/approval-results/${resultRef}/ack`;
    const ackId = randomUUID();
    const ackBody = { ...binding, ackId };
    const ack = await post(ackPath, ackBody, { 'OpenKey-Session-Proof': proof('ack', ackPath, resultRef, ackId) });
    expect(ack.status).toBe(200);
    expect(await ack.json()).toEqual({ status: 'acknowledged', ackId });
    expect(await (await post(ackPath, ackBody, { 'OpenKey-Session-Proof': proof('ack', ackPath, resultRef, ackId) })).json()).toEqual({ status: 'acknowledged', ackId });
    expect((await prisma.approvalRequest.findUniqueOrThrow({ where: { id } })).encryptedResult).toBeNull();
    expect((await post(fetchPath, binding, { 'OpenKey-Session-Proof': proof('fetch', fetchPath, resultRef) })).status).toBe(409);
    await prisma.$disconnect();
  }, 110_000);
}
