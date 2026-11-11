// TC-2234: a share invitation request through the real link path. /load and /deny open the sealed request with
// share-envelope's resolveLink from a loopback links service, then the owner approves it through /api/delegate.
import { expect, test } from 'bun:test';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';
import { canonicalize } from '@tinycloud/share-envelope';
import { buildShortLink, prepareLinkRecord, signerFromJwk } from '@tinycloud/share-envelope/links';
import { z } from 'zod';

const LINKS_ORIGIN = 'https://links.example.test';
const VIEWER_ORIGIN = 'https://openkey.example.test';

// A fresh process avoids Bun's process-wide route/auth mocks in the unit lane.
if (!process.env.TC2234_SHARE_INVITATION_LOAD_CHILD) {
  test('share invitation requests load, decline and approve through the real link path', async () => {
    const directory = await mkdtemp('/var/tmp/TC2234-openkey-load-');
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: resolve(import.meta.dir, '../../../..'),
        env: { ...process.env, TC2234_SHARE_INVITATION_LOAD_CHILD: directory, HOME: directory, TC_HOME: directory, COURIER_HOME: directory, TMPDIR: directory,
          BUN_INSTALL_CACHE_DIR: join(directory, 'bun-cache'), NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: 'http://localhost:3326', BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
          WEBAUTHN_ORIGIN: 'http://localhost:5180', WEBAUTHN_RP_ID: 'localhost', CORS_ORIGIN: 'http://localhost:5180',
          APPROVAL_RESULT_RETENTION_SECONDS: '600', TINYCLOUD_BOOTSTRAP_ON_SIGN: 'off',
          APPROVAL_LINKS_API_ORIGIN: LINKS_ORIGIN, APPROVAL_OPENKEY_ORIGIN: VIEWER_ORIGIN,
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
  test('owner loads, declines and approves share invitation requests opened with resolveLink', async () => {
    const directory = process.env.TC2234_SHARE_INVITATION_LOAD_CHILD!;
    const root = resolve(import.meta.dir, '../../../..');
    const database = new PGlite(join(directory, 'db'));
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    await database.close();

    // The links service: the sealed records this test publishes, served on loopback only.
    const records = new Map<string, { header: unknown; signature: unknown; body: string }>();
    const links = Bun.serve({
      hostname: '127.0.0.1', port: 0,
      fetch(request) {
        const match = /^\/v1\/links\/([a-z2-7]{26})$/.exec(new URL(request.url).pathname);
        const record = match && request.method === 'GET' ? records.get(match[1]!) : undefined;
        if (!record) return new Response(null, { status: 404 });
        // The links service sends the signed header as canonical JSON, which resolveLink requires.
        const header = Buffer.from(canonicalize({ header: record.header, signature: record.signature })).toString('base64url');
        return new Response(Buffer.from(record.body, 'base64url'), { headers: { 'content-type': 'application/octet-stream', 'x-link-record': header } });
      },
    });
    process.env.APPROVAL_LINKS_LOCAL_TRANSPORT = `http://127.0.0.1:${links.port}`;

    // The app's auth/database/TEE singletons must capture the isolated child environment only after its tracked
    // schema exists, not at static import.
    const { createPrismaClient } = await import('@openkey/db');
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
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
    const apiOrigin = process.env.BETTER_AUTH_URL!;
    const post = (path: string, payload: unknown, headers: Record<string, string> = {}) =>
      app.fetch(new Request(apiOrigin + path, { method: 'POST', headers: { 'content-type': 'application/json', origin: process.env.WEBAUTHN_ORIGIN!, ...headers }, body: JSON.stringify(payload) }));

    const pair = generateKeyPairSync('ed25519');
    const signer = signerFromJwk(pair.privateKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string; d: string });
    const targetJwk = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: pair.publicKey.export({ format: 'jwk' }).x! };
    const relay = await crypto.subtle.exportKey('jwk', (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])).publicKey);
    const linkExpiresAt = new Date(Math.floor((Date.now() + 2 * 3600_000) / 1000) * 1000);
    const acceptanceExpiresAt = new Date(linkExpiresAt.getTime() - 3600_000).toISOString();
    const invitation = (invitationId: string) => ({ kind: 'share-invitation', version: 1, invitationId, recipientEmail: 'alex@example.test',
      subjectKind: 'session', subjectName: 'Project notes', acceptanceExpiresAt, accessExpiresAt: acceptanceExpiresAt });
    const requestBody = (extra: Record<string, unknown>) => ({
      issuer: signer.did, requestVersion: 1, targetDid: signer.did, targetPublicJwk: targetJwk, nodeOrigin: 'https://node.example.test',
      grantLifetimeSeconds: 7200, resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relay.x, y: relay.y }, ...extra,
    });
    /** Seals `body` as an approval request link and serves it; returns the reference the page sends to /load. */
    async function publish(id: string, body: unknown): Promise<string> {
      const sealed = await prepareLinkRecord({ type: 'openkey-approval-request', issuerKey: signer, apiOrigin: LINKS_ORIGIN, expiresAt: linkExpiresAt, plaintext: new TextEncoder().encode(JSON.stringify(body)) });
      records.set(id, sealed.record as { header: unknown; signature: unknown; body: string });
      return buildShortLink({ origin: VIEWER_ORIGIN, type: 'openkey-approval-request', id, key: sealed.key, bodyCid: sealed.bodyCid }).slice(VIEWER_ORIGIN.length);
    }
    const load = (id: string, reference: string) => post(`/api/approval-requests/${id}/load`, { reference });

    // A request without an invitation loads as before.
    const plainId = 'aaaaaaaaaaaaaaaaaaaaaaaaaa';
    const plain = await load(plainId, await publish(plainId, requestBody({ permissions: [{ service: 'tinycloud.kv', space: 'synthetic', path: 'notes', actions: ['tinycloud.kv/get'] }] })));
    expect(plain.status, await plain.clone().text()).toBe(200);

    // An invitation request that also names a permission is refused when it is opened.
    const namedId = 'bbbbbbbbbbbbbbbbbbbbbbbbbb';
    const named = await load(namedId, await publish(namedId, requestBody({ context: invitation('01JC5Z8Q0000000000000000AA'),
      permissions: [{ service: 'tinycloud.encryption', space: 'encryption', path: `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default/share/${'0'.repeat(32)}`, actions: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'] }] })));
    expect(named.status).toBe(400);
    expect(await prisma.approvalRequest.findUnique({ where: { id: namedId } })).toBeNull();

    // A declined invitation stays declined: /load says so and /prepare refuses it.
    const declinedId = 'cccccccccccccccccccccccccc';
    const declinedReference = await publish(declinedId, requestBody({ permissions: [], context: invitation('01JC5Z8Q0000000000000000BB') }));
    expect((await load(declinedId, declinedReference)).status).toBe(200);
    const denied = await post(`/api/approval-requests/${declinedId}/deny`, { reference: declinedReference }, { cookie });
    expect(denied.status, await denied.clone().text()).toBe(200);
    expect(await (await load(declinedId, declinedReference)).json()).toMatchObject({ denied: true });
    const prepareDeclined = await post('/api/delegate/prepare', { keyId: ownerKey.id, jwk: targetJwk, host: 'https://node.example.test', expiry: '7200s', approvalRequestId: declinedId }, { cookie });
    expect(prepareDeclined.status).toBe(410);
    expect(await prepareDeclined.json()).toMatchObject({ code: 'expired_request' });

    // An open invitation loads with its context and no permissions, and the owner approves one OpenKey-issued key.
    const openId = 'dddddddddddddddddddddddddd';
    const loaded = await load(openId, await publish(openId, requestBody({ permissions: [], context: invitation('01JC5Z8Q0000000000000000CC') })));
    expect(loaded.status, await loaded.clone().text()).toBe(200);
    const view = z.object({ request: z.object({ permissions: z.array(z.unknown()), context: z.object({ recipientEmail: z.string() }).passthrough() }).passthrough() }).passthrough().parse(await loaded.json());
    expect(view.request.permissions).toEqual([]);
    expect(view.request.context).toEqual(invitation('01JC5Z8Q0000000000000000CC'));
    const prepareBody = { keyId: ownerKey.id, jwk: targetJwk, host: 'https://node.example.test', expiry: '7200s', approvalRequestId: openId };
    const preparedResponse = await post('/api/delegate/prepare', prepareBody, { cookie });
    expect(preparedResponse.status, await preparedResponse.clone().text()).toBe(200);
    const prepared = z.object({ prepared: z.object({ siwe: z.string() }).passthrough(), authorizationContext: z.object({ token: z.string() }), selectedActionKeys: z.array(z.string()) }).parse(await preparedResponse.json());
    const approved = await post('/api/delegate', { ...prepareBody, protocolVersion: 1, prepared: prepared.prepared, authorizationContextToken: prepared.authorizationContext.token, selectedActionIds: prepared.selectedActionKeys }, { cookie });
    expect(approved.status, await approved.clone().text()).toBe(200);
    expect(parsePreparedRecap(prepared.prepared.siwe).map((entry) => entry.path)).toEqual([expect.stringMatching(new RegExp(`^urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default/share/[0-9a-f]{32}$`))]);
    expect((await prisma.approvalRequest.findUniqueOrThrow({ where: { id: openId } })).resultRef).not.toBeNull();
    // The owner signed the binding to this request: its id and the CID of the sealed body /load opened.
    const stored = await prisma.approvalRequest.findUniqueOrThrow({ where: { id: openId } });
    expect(z.object({ siwe: z.string() }).passthrough().parse(await approved.json()).siwe.match(/^Request ID: (.+)$/gm))
      .toEqual([`Request ID: urn:tinycloud:approval-request:${openId}:${stored.bodyCid}`]);

    // A file invitation whose access lasts six days past acceptance loads and keeps that access; one that ends
    // before acceptance is refused.
    const fileAccess = new Date(Date.parse(acceptanceExpiresAt) + 6 * 24 * 3600_000).toISOString();
    const fileId = 'eeeeeeeeeeeeeeeeeeeeeeeeee';
    const fileLoaded = await load(fileId, await publish(fileId, requestBody({ permissions: [], context: { ...invitation('01JC5Z8Q0000000000000000DD'), subjectKind: 'file', accessExpiresAt: fileAccess } })));
    expect(fileLoaded.status, await fileLoaded.clone().text()).toBe(200);
    expect(await fileLoaded.json()).toMatchObject({ request: { context: { subjectKind: 'file', acceptanceExpiresAt, accessExpiresAt: fileAccess } } });
    const earlyId = 'ffffffffffffffffffffffffff';
    const early = await load(earlyId, await publish(earlyId, requestBody({ permissions: [], context: { ...invitation('01JC5Z8Q0000000000000000EE'), subjectKind: 'file', accessExpiresAt: new Date(Date.parse(acceptanceExpiresAt) - 1000).toISOString() } })));
    expect(early.status).toBe(400);
    // File access up to the shared policy-root limit (POLICY_ROOT_MAX_LIFETIME_SECONDS, 31 days) from the link's
    // issue time loads and is kept exactly; a longer one is refused at /load and nothing is registered.
    const fitsId = 'gggggggggggggggggggggggggg';
    const fitsAccess = new Date(Math.floor((Date.now() + 31 * 24 * 3600_000 - 30_000) / 1000) * 1000).toISOString();
    const fits = await load(fitsId, await publish(fitsId, requestBody({ permissions: [], context: { ...invitation('01JC5Z8Q0000000000000000FF'), subjectKind: 'file', accessExpiresAt: fitsAccess } })));
    expect(fits.status, await fits.clone().text()).toBe(200);
    expect(await fits.json()).toMatchObject({ request: { context: { accessExpiresAt: fitsAccess } } });
    const longId = 'hhhhhhhhhhhhhhhhhhhhhhhhhh';
    const longAccess = new Date(Math.floor((Date.now() + 35 * 24 * 3600_000) / 1000) * 1000).toISOString();
    const long = await load(longId, await publish(longId, requestBody({ permissions: [], context: { ...invitation('01JC5Z8Q0000000000000000GG'), subjectKind: 'file', accessExpiresAt: longAccess } })));
    expect(long.status).toBe(400);
    expect(long.headers.get('content-type')).toStartWith('application/json');
    expect(await long.json()).toEqual({
      code: 'invitation_access_too_long',
      error: "This invitation asks for file access longer than 31 days, which OpenKey can't approve. Ask the app to send a new invitation for 31 days or less.",
    });
    // Nothing was stored, so nothing can be prepared or approved for it.
    expect(await prisma.approvalRequest.findUnique({ where: { id: longId } })).toBeNull();
    const longPrepare = await post('/api/delegate/prepare', { keyId: ownerKey.id, jwk: targetJwk, host: 'https://node.example.test', expiry: '7200s', approvalRequestId: longId }, { cookie });
    expect(longPrepare.status).toBe(410);

    links.stop(true);
    await prisma.$disconnect();
  }, 110_000);
}
