import { afterAll, beforeAll, beforeEach, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';
import { FIRST_PARTY_PROVISION_NATIVE_CLIENTS } from '../services/provision-authority';

const root = resolve(import.meta.dir, '../../../..');
// P5: a native client's consent sets the owner's space up on the node only for a first-party native client: its exact
// client id AND its exact redirect URI together. Real HTTP routes and tracked migrations on PGlite; the node is a loopback
// stand-in that records every request it gets, so "nothing was set up" is "the node got no peer lookup and no host
// delegation".

if (!process.env.OPENKEY_NATIVE_PROVISION_TEST_CHILD) {
  test('native consent hosts a space only for a first-party native client (pglite)', async () => {
    const run = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env, OPENKEY_NATIVE_PROVISION_TEST_CHILD: '1', NODE_ENV: 'test', TEE_MODE: 'development',
        OPENKEY_RENEWAL_LEASES: 'enabled', BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'native-provision-test-signing-secret-0123456789',
        WEBAUTHN_RP_ID: 'openkey.test', WEBAUTHN_ORIGIN: 'https://openkey.test', CORS_ORIGIN: 'https://openkey.test',
        ADMIN_API_KEY: 'native-provision-admin-key', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
      },
      stdout: 'pipe', stderr: 'pipe',
    });
    const [stdout, stderr, status] = await Promise.all([new Response(run.stdout).text(), new Response(run.stderr).text(), run.exited]);
    expect(status, stdout + stderr).toBe(0);
  }, 300_000);
} else {
  const directory = await mkdtemp('/var/tmp/openkey-native-provision-');
  const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
    .filter(entry => entry.isDirectory()).map(entry => entry.name).sort();
  const migrationSql = await Promise.all(migrations.map(name => readFile(join(root, 'packages/db/prisma/migrations', name, 'migration.sql'), 'utf8')));
  const connection = new PGlite(directory);
  try { for (const sql of migrationSql) await connection.exec(sql); }
  finally { await connection.close(); }
  process.env.DATABASE_URL = `pglite:${directory}`;
  delete process.env.OPENKEY_DATABASE_SCHEMA;

  const API = 'https://api.openkey.test';
  const ORIGIN = 'https://openkey.test';
  const ISSUER = `${API}/api/auth`;
  const CONSENT = '/api/oauth/tinycloud/requests';
  const [FIRST_PARTY] = FIRST_PARTY_PROVISION_NATIVE_CLIENTS;
  const OTHER_REDIRECT = 'xyz.tinycloud.other://openkey/callback';
  const USER = 'native-provision-owner';
  const SCOPE = 'tinycloud:delegation';
  const DAY = 86_400;
  const VERIFIER = 'native-provision-0123456789-0123456789-0123456789-01';
  const permissions = [
    { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
    { service: 'tinycloud.kv', space: 'applications', path: 'xyz.tinycloud.test/', actions: ['tinycloud.kv/get'] },
  ];
  const nodeIdentity = {
    nodeDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    renewerDid: 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp',
    renewerPublicKey: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik',
    renewerEpoch: 0,
  };
  let prisma: PrismaClient;
  let app: { fetch(request: Request): Response | Promise<Response> };
  let cookie: string;
  let address: string;
  let clientId = '';
  let redirectUri = '';
  // Every request the node received, in order: `peer` for the peer lookup, `delegate` for a delegation posted to it.
  let nodeRequests: string[] = [];
  let spaceHosted = false;

  const node = Bun.serve({
    hostname: '127.0.0.1', port: 0,
    async fetch(request) {
      const { pathname } = new URL(request.url);
      if (pathname.startsWith('/peer/generate/')) { nodeRequests.push('peer'); return new Response(nodeIdentity.nodeDid); }
      if (pathname === '/delegate') {
        nodeRequests.push('delegate');
        const space = `tinycloud:pkh:eip155:1:${address}:applications`;
        // A session delegation for a space the node does not host is skipped; the host delegation then creates it.
        const isHostDelegation = nodeRequests.filter(entry => entry === 'delegate').length === 2;
        if (isHostDelegation) spaceHosted = true;
        return Response.json(spaceHosted && !isHostDelegation ? { activated: [space], skipped: [] } : { activated: [], skipped: [space] });
      }
      if (pathname === '/info') return Response.json({ nodeId: nodeIdentity.nodeDid });
      if (pathname === '/.well-known/tinycloud/node-keys') return Response.json(nodeIdentity);
      return new Response(null, { status: 404 });
    },
  });
  const host = node.url.origin;
  const ceiling = { version: 1, appId: 'xyz.tinycloud.test', tinycloudHost: host,
    kv: { paths: ['xyz.tinycloud.test/'], actions: ['get'] }, maxDelegationTtlSeconds: DAY, grantLifetimeSeconds: 30 * DAY };

  const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  function makeDevice() {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const { x } = publicKey.export({ format: 'jwk' }) as { x: string };
    const jwk = { kty: 'OKP', crv: 'Ed25519', x };
    const jkt = hash(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x }));
    return {
      jwk,
      proof(credential: string, path: string) {
        const head = encode({ typ: 'openkey-session-proof+jwt', alg: 'EdDSA', kid: jkt });
        const payload = encode({ jti: randomUUID().replaceAll('-', ''), iat: Math.floor(Date.now() / 1000), htm: 'POST',
          htu: `${ISSUER}${path}`, client_id: clientId, cred_hash: hash(credential) });
        return `${head}.${payload}.${sign(null, Buffer.from(`${head}.${payload}`), privateKey).toString('base64url')}`;
      },
    };
  }
  function form(path: string, fields: Record<string, string>, proof?: string) {
    return app.fetch(new Request(`${ISSUER}${path}`, {
      method: 'POST', body: new URLSearchParams(fields),
      headers: { origin: 'capacitor://localhost', ...(proof && { 'OpenKey-Session-Proof': proof }) },
    }));
  }
  function browser(path: string, data: object, method = 'POST') {
    return app.fetch(new Request(`${API}${path}`, {
      method, body: JSON.stringify(data),
      headers: { cookie, origin: ORIGIN, 'Content-Type': 'application/json' },
    }));
  }
  function par(device: ReturnType<typeof makeDevice>) {
    return form('/oauth2/par', {
      client_id: clientId, response_type: 'code', redirect_uri: redirectUri, state: randomUUID(),
      code_challenge: hash(VERIFIER), code_challenge_method: 'S256', scope: `openid offline_access ${SCOPE}`,
      authorization_details: JSON.stringify([{ type: 'tinycloud_delegation', session_key: device.jwk, permissions, ttl_seconds: 3600 }]),
    });
  }
  async function request() {
    const device = makeDevice();
    const pushed = await par(device);
    expect(pushed.status, await pushed.clone().text()).toBe(201);
    const { request_uri } = await pushed.json() as { request_uri: string };
    const auth = await app.fetch(new Request(`${ISSUER}/oauth2/authorize?${new URLSearchParams({ client_id: clientId, request_uri })}`, { headers: { cookie } }));
    expect(auth.status, await auth.clone().text()).toBe(302);
    const consent = new URL(auth.headers.get('location')!);
    expect(consent.pathname).toBe('/oauth/consent');
    const id = request_uri.split(':').at(-1)!;
    return { device, id, consent };
  }

  interface Preview {
    revision: number; digest: string; sessionSiwe: string; hostPlan?: { hostSiwe: string } | null;
  }
  async function prepare(id: string) {
    const response = await browser(`${CONSENT}/${id}/prepare`, {});
    expect(response.status, await response.clone().text()).toBe(200);
    return await response.json() as Preview;
  }
  function approve(id: string, preview: Preview) {
    return browser(`${CONSENT}/${id}/approve`, {
      revision: preview.revision, digest: preview.digest, sessionSiwe: preview.sessionSiwe, hostSiwe: preview.hostPlan?.hostSiwe,
    });
  }

  /** A native client registered with `id` and `redirect`, and an owner with no TinyCloud space. */
  async function registerClient(id: string | null, redirect: string) {
    redirectUri = redirect;
    const response = await app.fetch(new Request(`${API}/api/admin/oauth/clients`, {
      method: 'POST', headers: { Authorization: 'Bearer native-provision-admin-key', 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Native test', type: 'native', redirectUris: [redirect], tinycloudNativeDelegation: ceiling }),
    }));
    expect(response.status, await response.clone().text()).toBe(201);
    clientId = (await response.json() as { client: { clientId: string } }).client.clientId;
    // The admin route mints the client id; the first-party id is one fixed value, so it is set on the row directly.
    if (id) {
      await prisma.oauthClient.update({ where: { clientId }, data: { clientId: id } });
      clientId = id;
    }
  }

  beforeAll(async () => {
    const { auth } = await import('../auth');
    app = (await import('../index')).default;
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
    const key = generatePrivateKey();
    address = getAddressFromPrivateKey(key);
    const context = await auth.$context;
    const access = randomUUID();
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, access, context.secret)).split(';')[0]!;
    await prisma.user.create({ data: { id: USER, email: 'native-provision@example.test', name: 'Native owner', emailVerified: true } });
    await prisma.session.create({ data: { id: USER, token: access, userId: USER, expiresAt: new Date(Date.now() + 3_600_000) } });
    // The owner has accepted the Terms, so consent is not sent to the Terms screen first.
    await prisma.termsAcceptance.create({ data: { id: randomUUID(), userId: USER, documentId: 'terms', version: '2026-11-22',
      textSha256: '2bdaf7a5f3921c902c1d16135a543a67094802e3acaee308940dc4e7f72ae9cc', surface: 'web', appVersion: 'test' } });
    const sealingContext = randomUUID().replaceAll('-', '').padEnd(43, 'A');
    const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    await prisma.ethereumKey.create({ data: { id: 'managed-native-provision-key', address, userId: USER, publicKey: '0x1',
      sealedBlob: await seal(key, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
  }, 30_000);

  beforeEach(async () => {
    nodeRequests = [];
    spaceHosted = false;
    // The owner has no TinyCloud space: no bootstrap row, and the node hosts nothing.
    await prisma.tinyCloudNativeRequest.deleteMany({});
    await prisma.oauthClient.deleteMany({});
  });

  afterAll(async () => {
    node.stop(true);
    await prisma?.$disconnect();
    await rm(directory, { recursive: true, force: true });
  });

  /** Consent for an owner with no space: what the page was shown, and what the approval answered. */
  async function consentFor(id: string | null, redirect: string) {
    await registerClient(id, redirect);
    const flow = await request();
    const preview = await prepare(flow.id);
    const peersAfterPrepare = nodeRequests.filter(entry => entry === 'peer').length;
    const approved = await approve(flow.id, preview);
    expect(approved.status, await approved.clone().text()).toBe(200);
    return { preview, peersAfterPrepare, answer: await approved.json() as { status: string; hosting: string } };
  }

  test('the first-party native client has its space hosted', async () => {
    const { preview, peersAfterPrepare, answer } = await consentFor(FIRST_PARTY!.clientId, FIRST_PARTY!.redirectUri);

    expect(preview.hostPlan).toBeTruthy();
    expect(peersAfterPrepare).toBe(1);
    expect(answer).toMatchObject({ status: 'APPROVED', hosting: 'created' });
    expect(nodeRequests).toEqual(['peer', 'delegate', 'delegate', 'delegate']);
  }, 30_000);

  test('another native client is approved with nothing set up on the node', async () => {
    const { preview, peersAfterPrepare, answer } = await consentFor(null, 'xyz.tinycloud.test://openkey/callback');

    expect(preview.hostPlan ?? null).toBeNull();
    expect(peersAfterPrepare).toBe(0);
    // The signature is issued; the space is not hosted, so the device is told hosting failed (the SDK ends that sign-in as SPACE_UNAVAILABLE).
    expect(answer).toMatchObject({ status: 'APPROVED', hosting: 'failed' });
    expect(nodeRequests).toEqual(['delegate']);
  }, 30_000);

  test('the first-party client id on another redirect URI is not first-party', async () => {
    const { preview, answer } = await consentFor(FIRST_PARTY!.clientId, OTHER_REDIRECT);

    expect(preview.hostPlan ?? null).toBeNull();
    // The signature is issued; the space is not hosted, so the device is told hosting failed (the SDK ends that sign-in as SPACE_UNAVAILABLE).
    expect(answer).toMatchObject({ status: 'APPROVED', hosting: 'failed' });
    expect(nodeRequests).toEqual(['delegate']);
  }, 30_000);

  test('the first-party redirect URI on another client id is not first-party', async () => {
    const { preview, answer } = await consentFor(null, FIRST_PARTY!.redirectUri);

    expect(preview.hostPlan ?? null).toBeNull();
    // The signature is issued; the space is not hosted, so the device is told hosting failed (the SDK ends that sign-in as SPACE_UNAVAILABLE).
    expect(answer).toMatchObject({ status: 'APPROVED', hosting: 'failed' });
    expect(nodeRequests).toEqual(['delegate']);
  }, 30_000);
}
