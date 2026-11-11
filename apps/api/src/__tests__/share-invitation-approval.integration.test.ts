// TC-2234: a share invitation approval through the real API: the owner's managed key signs `key.create` and
// `decrypt` on one share key OpenKey generated, and the requester's encrypted result carries that SIWE.
import { expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';
import { signerFromJwk, prepareLinkRecord, openLinkRecord } from '@tinycloud/share-envelope/links';
import { z } from 'zod';
import { SiweMessage } from 'siwe';

// A fresh process avoids Bun's process-wide route/auth mocks in the unit lane.
if (!process.env.TC2234_SHARE_INVITATION_CHILD) {
  test('a share invitation approval signs one OpenKey-generated share key, once', async () => {
    const directory = await mkdtemp('/var/tmp/TC2234-openkey-api-');
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: resolve(import.meta.dir, '../../../..'),
        env: { ...process.env, TC2234_SHARE_INVITATION_CHILD: directory, HOME: directory, TC_HOME: directory, COURIER_HOME: directory, TMPDIR: directory,
          BUN_INSTALL_CACHE_DIR: join(directory, 'bun-cache'), NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: 'http://localhost:3325', BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
          WEBAUTHN_ORIGIN: 'http://localhost:5179', WEBAUTHN_RP_ID: 'localhost', CORS_ORIGIN: 'http://localhost:5179',
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
  test('owner approval of a share invitation through /api/delegate', async () => {
    const directory = process.env.TC2234_SHARE_INVITATION_CHILD!;
    const root = resolve(import.meta.dir, '../../../..');
    const database = new PGlite(join(directory, 'db'));
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    await database.close();
    // The app's auth/database/TEE singletons must capture the isolated child environment only after its tracked
    // schema exists, not at static import.
    const { createPrismaClient } = await import('@openkey/db');
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
    const { createPrismaApprovalRequestStore } = await import('../services/approval-request-store');
    const { parseApprovalRequestV1 } = await import('../services/share-invitation');
    const { parsePreparedRecap } = await import('../routes/delegate-session');
    const { auth } = await import('../auth');
    const app = (await import('../index')).default;
    const prisma = createPrismaClient();
    const userId = randomUUID();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, emailVerified: true } });
    const privateKey = generatePrivateKey();
    const address = getAddressFromPrivateKey(privateKey);
    const sealingContext = randomBytes(32).toString('base64url');
    const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    const ownerKey = await prisma.ethereumKey.create({ data: { userId, address, publicKey: '0x1', sealedBlob: await seal(privateKey, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
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
    const linkExpiresAt = new Date(Math.floor((Date.now() + 2 * 3600_000) / 1000) * 1000);
    const acceptanceExpiresAt = new Date(linkExpiresAt.getTime() - 3600_000).toISOString();
    const body = {
      issuer: signer.did, requestVersion: 1, targetDid: signer.did, targetPublicJwk: targetJwk, nodeOrigin: 'https://node.example.test',
      permissions: [], grantLifetimeSeconds: 7200, resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x, y: relayJwk.y },
      context: { kind: 'share-invitation', version: 1, invitationId: '01JC5Z8Q0000000000000000AB', recipientEmail: 'alex@example.test',
        subjectKind: 'session', subjectName: 'Project notes', acceptanceExpiresAt, accessExpiresAt: acceptanceExpiresAt },
    };
    const sealed = await prepareLinkRecord({ type: 'openkey-approval-request', issuerKey: signer, apiOrigin: 'https://api.tinycloud.xyz', expiresAt: linkExpiresAt, plaintext: new TextEncoder().encode(JSON.stringify(body)) });
    const opened = await openLinkRecord(sealed.record, sealed.key);
    const id = 'abcdefghijklmnopqrstuvwxyz';
    // The request /load registers: the same parser, on the bytes the requester sealed.
    await createPrismaApprovalRequestStore(prisma).register({ id, bodyCid: opened.header.bodyCid, issuer: opened.header.issuer, request: parseApprovalRequestV1(opened.value, { issuer: opened.header.issuer, linkIssuedAt: new Date(opened.header.issuedAt), linkExpiresAt: new Date(opened.header.expiresAt) }), expiresAt: new Date(opened.header.expiresAt), createdAt: new Date(), resultRef: null, encryptedResult: null, resultExpiresAt: null });

    const apiOrigin = process.env.BETTER_AUTH_URL!;
    const post = (path: string, payload: unknown, headers: Record<string, string> = {}) =>
      app.fetch(new Request(apiOrigin + path, { method: 'POST', headers: { 'content-type': 'application/json', origin: process.env.WEBAUTHN_ORIGIN!, cookie, ...headers }, body: JSON.stringify(payload) }));
    const owner = `did:pkh:eip155:1:${address}`;
    const shareKey = new RegExp(`^urn:tinycloud:encryption:${owner}:default/share/([0-9a-f]{32})$`);
    const preparedSchema = z.object({
      prepared: z.object({ siwe: z.string() }).passthrough(),
      authorizationContext: z.object({ token: z.string() }),
      selectedActionKeys: z.array(z.string()),
    });
    const prepareBody = { keyId: ownerKey.id, jwk: targetJwk, host: body.nodeOrigin, expiry: '7200s', approvalRequestId: id };
    async function prepare() {
      const response = await post('/api/delegate/prepare', prepareBody);
      expect(response.status, await response.clone().text()).toBe(200);
      const prepared = preparedSchema.parse(await response.json());
      const entries = parsePreparedRecap(prepared.prepared.siwe);
      expect(entries).toHaveLength(1);
      expect(entries[0]!.actions.sort()).toEqual(['tinycloud.encryption/decrypt', 'tinycloud.encryption/key.create']);
      const keyId = shareKey.exec(entries[0]!.path)?.[1];
      expect(keyId).toBeDefined();
      expect(Date.parse(new SiweMessage(prepared.prepared.siwe).expirationTime!)).toBeLessThanOrEqual(Date.parse(acceptanceExpiresAt));
      return { prepared, keyId: keyId! };
    }

    // A requester's own share key is refused, even one it names in the approval body.
    const named = await post('/api/delegate/prepare', { ...prepareBody, permissions: [{ service: 'tinycloud.encryption', path: `urn:tinycloud:encryption:${owner}:default/share/${'0'.repeat(32)}`, actions: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'] }] });
    expect(named.status).toBe(400);
    expect(await named.json()).toMatchObject({ code: 'request_binding' });

    const first = await prepare();
    const second = await prepare();
    expect(second.keyId).not.toBe(first.keyId);

    const approval = (prepared: z.infer<typeof preparedSchema>) => ({ ...prepareBody, protocolVersion: 1, prepared: prepared.prepared, authorizationContextToken: prepared.authorizationContext.token, selectedActionIds: prepared.selectedActionKeys });
    // A browser wallet signature cannot approve an invitation: only a key OpenKey holds signs what it prepared.
    const wallet = await post('/api/delegate/complete', { ...approval(first.prepared), signature: `0x${'11'.repeat(65)}` });
    expect(wallet.status).toBe(400);
    expect(await wallet.json()).toMatchObject({ code: 'request_binding' });
    const approved = await post('/api/delegate', approval(second.prepared));
    expect(approved.status, await approved.clone().text()).toBe(200);
    const delegation = z.object({ ownerDid: z.string(), siwe: z.string() }).passthrough().parse(await approved.json());
    expect(delegation.siwe).toBe(second.prepared.prepared.siwe);
    expect(delegation.ownerDid).toBe(owner);

    // One approval per request: an earlier preview of the same request cannot be signed as well.
    const again = await post('/api/delegate', approval(first.prepared));
    expect(again.status).toBe(410);

    function proof(action: 'discover' | 'fetch', path: string, ref = '') {
      const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');
      const head = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: jkt, typ: 'openkey-session-proof+jwt' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ client_id: 'openkey-approval-result-v1', cred_hash: createHash('sha256').update(JSON.stringify([action, id, opened.header.bodyCid, ref, ''])).digest('base64url'), htm: 'POST', htu: apiOrigin + path, iat: Math.floor(Date.now() / 1000), jti: randomBytes(24).toString('base64url') })).toString('base64url');
      return `${head}.${payload}.${sign(null, Buffer.from(`${head}.${payload}`), pair.privateKey).toString('base64url')}`;
    }
    const resultPath = `/api/approval-requests/${id}/result`;
    const discovered = await post(resultPath, { bodyCid: opened.header.bodyCid }, { 'OpenKey-Session-Proof': proof('discover', resultPath) });
    expect(discovered.status).toBe(200);
    const { resultRef } = z.object({ resultRef: z.string() }).parse(await discovered.json());
    const fetchPath = `/api/approval-results/${resultRef}/fetch`;
    const fetched = await post(fetchPath, { requestId: id, bodyCid: opened.header.bodyCid }, { 'OpenKey-Session-Proof': proof('fetch', fetchPath, resultRef) });
    expect(fetched.status).toBe(200);
    const { relay } = z.object({ relay: z.object({ ephemeralPublicJwk: z.object({ kty: z.literal('EC'), crv: z.literal('P-256'), x: z.string(), y: z.string() }).passthrough(), nonce: z.string(), ciphertext: z.string() }).passthrough() }).passthrough().parse(await fetched.json());
    const ephemeral = await crypto.subtle.importKey('jwk', relay.ephemeralPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: ephemeral }, relayPair.privateKey, 256);
    const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const label = new TextEncoder().encode(id);
    const aes = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: label, info: new TextEncoder().encode('openkey-device-relay-v1') }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const result = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(relay.nonce, 'base64url'), additionalData: label }, aes, Buffer.from(relay.ciphertext, 'base64url'))));
    const signed = parsePreparedRecap(result.delegation.siwe);
    expect(signed.map((entry) => entry.path)).toEqual([`urn:tinycloud:encryption:${owner}:default/share/${second.keyId}`]);
    expect(new SiweMessage(result.delegation.siwe).uri).toBe(`${signer.did}#${signer.did.slice('did:key:'.length)}`);
    await prisma.$disconnect();
  }, 110_000);
}
