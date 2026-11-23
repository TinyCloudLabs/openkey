import './tc1777-test-env';
import { afterAll, beforeAll, beforeEach, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { getAddress } from 'viem';
import { serializeSignedCookie } from 'better-call';
import type * as DatabaseModule from '@openkey/db';

// TC-4110. Renewal leases exist only for sign-in originals: a step-up approval never records one, even when its
// request row carries a renewalAsk. The revoke-pending sweep (services/native-delegation/revoke-pending.ts, the
// `Date.parse(record.expiresAt) <= now` clear in `attempt`) relies on this: it drops a pending revoke once OpenKey's
// recorded `expiresAt` has passed, which is only safe while nothing can extend a step-up delegation on the node. A
// lease is what extends one (the node renews it), so a step-up that could hold one would outlive that recorded end.
// The sign-in control below approves the same ask through the same consent route and must record a lease; without it
// the step-up assertions could pass because renewal is switched off or the node stub is wrong.
// Real migration chain on PGlite, real consent routes over HTTP, a stub node. Runs in a child process: other API
// tests replace @openkey/db and Better Auth globally.
const root = resolve(import.meta.dir, '../../../..');
const child = process.env.TC4110_NO_STEPUP_LEASE_TEST_CHILD === '1';

if (!child) {
  test('a step-up approval never holds a renewal lease, a sign-in approval of the same ask does (real migration chain)', async () => {
    const run = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env, TC4110_NO_STEPUP_LEASE_TEST_CHILD: '1', NODE_ENV: 'test', TEE_MODE: 'development', OPENKEY_RENEWAL_LEASES: 'enabled',
        BETTER_AUTH_URL: 'https://api.openkey.test', BETTER_AUTH_SECRET: 'tc4110-stepup-lease-isolated-test-secret-0123456789',
        WEBAUTHN_RP_ID: 'openkey.test', WEBAUTHN_ORIGIN: 'https://openkey.test', CORS_ORIGIN: 'https://openkey.test',
        ADMIN_API_KEY: 'tc4110-admin-key', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
      },
      stdout: 'pipe', stderr: 'pipe',
    });
    const [stdout, stderr, status] = await Promise.all([new Response(run.stdout).text(), new Response(run.stderr).text(), run.exited]);
    expect(status, stdout + stderr).toBe(0);
  }, 300_000);
} else {
  const directory = await mkdtemp(join(tmpdir(), 'openkey-tc4110-lease-'));
  let prisma: DatabaseModule.PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let clientId: string;
  let cookie: string;
  let address: `0x${string}`;
  const API = 'https://api.openkey.test';
  const ISSUER = `${API}/api/auth`;
  const CONSENT = `${API}/api/oauth/tinycloud/requests`;
  const HOST = 'https://tee.node.tinycloud.xyz';
  const HOME_REDIRECT = 'xyz.tinycloud.exo://openkey/callback';
  const STEPUP_REDIRECT = 'xyz.tinycloud.exo://openkey/stepup';
  const DELEGATION = 'tinycloud:delegation';
  const USER = 'nl-user';
  const EXPLORER = 'xyz.tinycloud.explorer';
  const DAY = 86_400;
  const ASK = { version: 1, leaseLifetimeSeconds: 90 * DAY, purpose: 'standing' } as const;
  const LEASED = { choice: 'leased', leaseLifetimeSeconds: 90 * DAY } as const;
  const nodeIdentity = {
    nodeDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    renewerDid: 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp',
    renewerPublicKey: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik',
    renewerEpoch: 0,
  };
  const homePermissions = [
    { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
    { service: 'tinycloud.kv', space: 'applications', path: 'xyz.tinycloud.home/', actions: ['tinycloud.kv/get'] },
  ];
  const explorerEntries = [
    { service: 'tinycloud.kv', space: 'public', path: '', actions: ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata'] },
  ];
  const ceiling = {
    version: 1, appId: 'xyz.tinycloud.home', tinycloudHost: HOST,
    kv: { paths: ['xyz.tinycloud.home/'], actions: ['get', 'list'] }, sql: null,
    maxDelegationTtlSeconds: 3600, grantLifetimeSeconds: 30 * DAY,
    stepUps: { [EXPLORER]: { public: { kv: { paths: [''], actions: ['get', 'list', 'metadata'] } } } },
  };
  const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
  const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const VERIFIER = 'tc4110-stepup-lease-verifier-0123456789-0123456789';
  type Device = { privateKey: KeyObject; jwk: { kty: 'OKP'; crv: 'Ed25519'; x: string }; jkt: string };

  function device(): Device {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const { x } = publicKey.export({ format: 'jwk' }) as { x: string };
    return { privateKey, jwk: { kty: 'OKP', crv: 'Ed25519', x }, jkt: hash(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })) };
  }

  function didKey(x: string) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let value = BigInt(`0x${Buffer.from([0xed, 0x01, ...Buffer.from(x, 'base64url')]).toString('hex')}`);
    let encoded = '';
    while (value > 0n) { encoded = alphabet[Number(value % 58n)] + encoded; value /= 58n; }
    return `did:key:z${encoded}`;
  }

  function proof(key: Device, token: string, path: string) {
    const header = b64({ typ: 'openkey-session-proof+jwt', alg: 'EdDSA', kid: key.jkt });
    const payload = b64({ jti: randomUUID().replaceAll('-', ''), iat: Math.floor(Date.now() / 1000), htm: 'POST',
      htu: `${ISSUER}${path.slice('/api/auth'.length)}`, client_id: clientId, cred_hash: hash(token) });
    return `${header}.${payload}.${sign(null, Buffer.from(`${header}.${payload}`), key.privateKey).toString('base64url')}`;
  }

  function post(path: string, fields: URLSearchParams, sessionProof?: string) {
    return app.fetch(new Request(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded',
      Origin: 'capacitor://localhost', ...(sessionProof ? { 'OpenKey-Session-Proof': sessionProof } : {}) }, body: fields.toString() }));
  }

  async function seedDevice(id: string, key: Device, token: string) {
    const did = didKey(key.jwk.x);
    await prisma.oauthRefreshToken.create({ data: { id: `${id}-refresh`, token: hash(token), clientId, userId: USER,
      scopes: ['openid', 'offline_access', DELEGATION], expiresAt: new Date(Date.now() + 7 * DAY * 1000) } });
    await prisma.tinyCloudNativeGrant.create({ data: { id, userId: USER, clientId, consentId: 'nl-consent', consentGeneration: 0n,
      keyId: 'nl-key', address, sessionDid: `${did}#${did.slice('did:key:'.length)}`, sessionJwk: key.jwk, sessionJkt: key.jkt,
      spaceId: `tinycloud:pkh:eip155:1:${address}:applications`, approvedPermissions: homePermissions, ttlSeconds: 3600, tinycloudHost: HOST,
      refreshTokenHash: hash(token), absoluteExpiresAt: new Date(Date.now() + 30 * DAY * 1000) } });
  }

  function consent(id: string, action: 'prepare' | 'approve', payload: Record<string, unknown> = {}) {
    return app.fetch(new Request(`${CONSENT}/${id}/${action}`, { method: 'POST',
      headers: { cookie, origin: 'https://openkey.test', 'content-type': 'application/json' }, body: JSON.stringify(payload) }));
  }
  async function authorize(requestUri: string) {
    const response = await app.fetch(new Request(`${ISSUER}/oauth2/authorize?${new URLSearchParams({ client_id: clientId, request_uri: requestUri })}`, { headers: { cookie } }));
    expect(response.status, await response.clone().text()).toBe(302);
  }
  interface Preview { revision: number; digest: string; sessionSiwe: string; renewal?: unknown; hostPlan?: { hostSiwe: string } | null }
  async function prepare(id: string, payload: Record<string, unknown> = {}) {
    const response = await consent(id, 'prepare', payload);
    expect(response.status, await response.clone().text()).toBe(200);
    return await response.json() as Preview;
  }
  const approval = (preview: Preview, renewal?: unknown) => ({ revision: preview.revision, digest: preview.digest, sessionSiwe: preview.sessionSiwe,
    hostSiwe: preview.hostPlan?.hostSiwe, ...(renewal === undefined ? {} : { renewal }) });

  // The node: it activates every space, answers its renewal identity, and takes any revoke.
  async function withNode<T>(run: () => Promise<T>) {
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: Request | URL | string) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      switch (url) {
        case `${HOST}/delegate`: return Response.json({ activated: [`tinycloud:pkh:eip155:1:${address}:applications`, `tinycloud:pkh:eip155:1:${address}:public`], skipped: [] });
        case `${HOST}/info`: return Response.json({ nodeId: nodeIdentity.nodeDid });
        case `${HOST}/.well-known/tinycloud/node-keys`: return Response.json(nodeIdentity);
        case `${HOST}/revoke`: return new Response(null, { status: 204 });
        default: throw new Error(`unexpected fetch ${url}`);
      }
    }) as typeof fetch;
    try { return await run(); } finally { globalThis.fetch = original; }
  }

  const leaseRows = async () => ({ leases: await prisma.renewalLease.count(), native: await prisma.nativeRenewalLease.count() });

  beforeAll(async () => {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    const database = new PGlite(directory);
    try { for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8')); }
    finally { await database.close(); }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    // The API modules open their database when loaded, so they are imported (dynamically) only after DATABASE_URL is set.
    const { mock } = await import('bun:test');
    const userRateLimit = await import('../services/native-delegation/user-rate-limit');
    mock.module('../services/native-delegation/user-rate-limit', () => ({ ...userRateLimit, nativeUserRetryAfter: () => 0 }));
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
    const { auth } = await import('../auth');
    app = (await import('../index')).default;
    await prisma.user.create({ data: { id: USER, email: 'nl@example.test', name: 'NL', emailVerified: true } });
    const sessionToken = randomUUID();
    await prisma.session.create({ data: { id: 'nl-session', token: sessionToken, userId: USER, expiresAt: new Date(Date.now() + 3_600_000) } });
    const context = await auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
    const privateKey = generatePrivateKey(); address = getAddress(getAddressFromPrivateKey(privateKey));
    const sealingContext = randomUUID().replaceAll('-', '').padEnd(43, 'A').slice(0, 43);
    const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    await prisma.ethereumKey.create({ data: { id: 'nl-key', userId: USER, address, publicKey: '0x1',
      sealedBlob: await seal(privateKey, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
    const response = await app.fetch(new Request(`${API}/api/admin/oauth/clients`, { method: 'POST',
      headers: { Authorization: 'Bearer tc4110-admin-key', 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Step-up Home', type: 'native', redirectUris: [HOME_REDIRECT, STEPUP_REDIRECT], tinycloudNativeDelegation: ceiling }) }));
    expect(response.status, await response.clone().text()).toBe(201);
    clientId = (await response.json() as { client: { clientId: string } }).client.clientId;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    await rm(directory, { recursive: true, force: true });
    delete process.env.OPENKEY_NATIVE_STEPUP_ENABLED;
    delete process.env.OPENKEY_RENEWAL_NODE_DID;
    delete process.env.OPENKEY_RENEWAL_RENEWER_DID;
  });

  beforeEach(async () => {
    process.env.OPENKEY_NATIVE_STEPUP_ENABLED = '1';
    process.env.OPENKEY_RENEWAL_LEASES = 'enabled';
    // The node's renewal identity is pinned for the production host the ceiling names.
    process.env.OPENKEY_RENEWAL_NODE_DID = nodeIdentity.nodeDid;
    process.env.OPENKEY_RENEWAL_RENEWER_DID = nodeIdentity.renewerDid;
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE "oauth_refresh_token", "oauth_access_token", "native_session_proof_jti", "oauth_consent", "renewal_lease",
      "tinycloud_native_grant", "tinycloud_native_request", "tinycloud_native_consent_generation", "tinycloud_bootstrap_state" CASCADE`);
    await prisma.tinyCloudBootstrapState.create({ data: { userId: USER, keyId: 'nl-key', address, chainId: 1, tinycloudHost: HOST,
      bootstrapVersion: 'test', status: 'complete', checkedAt: new Date(), completedAt: new Date() } });
    await prisma.oauthConsent.create({ data: { id: 'nl-consent', userId: USER, clientId, scopes: ['openid', 'offline_access', DELEGATION] } });
    await prisma.tinyCloudNativeConsentGeneration.create({ data: { userId: USER, clientId, generation: 0n } });
  });

  test('control: a sign-in approval of the ask records a renewal lease', async () => {
    const key = device();
    const pushed = await post('/api/auth/oauth2/par', new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: HOME_REDIRECT, state: 'a'.repeat(32), code_challenge: hash(VERIFIER), code_challenge_method: 'S256',
      scope: `openid offline_access ${DELEGATION}`,
      authorization_details: JSON.stringify([{ type: 'tinycloud_delegation', session_key: key.jwk, permissions: homePermissions, ttl_seconds: 3600, renewal: ASK }]),
    }));
    expect(pushed.status, await pushed.clone().text()).toBe(201);
    const { request_uri } = await pushed.json() as { request_uri: string };
    await authorize(request_uri);
    const id = request_uri.split(':').at(-1)!;
    expect(await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ kind: 'SIGNIN', renewalAsk: ASK });

    expect(await leaseRows()).toEqual({ leases: 0, native: 0 });
    const preview = await withNode(() => prepare(id, { renewal: LEASED }));
    const approved = await withNode(() => consent(id, 'approve', approval(preview, LEASED)));
    expect(approved.status, await approved.clone().text()).toBe(200);
    expect(await leaseRows()).toEqual({ leases: 1, native: 1 });
    const row = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } });
    expect(row.renewalLeaseCid).not.toBeNull();
  });

  // A step-up request for Explorer on a fresh grant, RESOLVED and prepared. The step-up endpoint takes no renewal ask,
  // so one is put on the row directly: the very ask the sign-in control carries.
  async function preparedStepUp(withAsk: boolean) {
    const key = device(); await seedDevice('g1', key, 'token-1');
    const response = await post('/api/auth/oauth2/tinycloud/stepup', new URLSearchParams({
      client_id: clientId, refresh_token: 'token-1', app_id: EXPLORER, permissions: JSON.stringify(explorerEntries),
      redirect_uri: STEPUP_REDIRECT, state: 'b'.repeat(32), code_challenge: hash(VERIFIER), code_challenge_method: 'S256',
    }), proof(key, 'token-1', '/api/auth/oauth2/tinycloud/stepup'));
    expect(response.status, await response.clone().text()).toBe(201);
    const { request_uri } = await response.json() as { request_uri: string };
    const id = request_uri.split(':').at(-1)!;
    if (withAsk) await prisma.tinyCloudNativeRequest.update({ where: { id }, data: { renewalAsk: ASK } });
    await authorize(request_uri);
    const preview = await withNode(() => prepare(id));
    expect(await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ kind: 'STEPUP', renewalAsk: withAsk ? ASK : null });
    return { id, preview };
  }

  test('control: a step-up approval goes through, with no renewal ask and no lease', async () => {
    const { id, preview } = await preparedStepUp(false);
    const approved = await withNode(() => consent(id, 'approve', approval(preview)));
    expect(approved.status, await approved.clone().text()).toBe(200);
    expect(await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: 'APPROVED', renewalLeaseCid: null });
    expect(await leaseRows()).toEqual({ leases: 0, native: 0 });
  });

  test('a step-up request that carries a renewalAsk records no renewal lease, whatever renewal the approval chooses', async () => {
    const { id, preview } = await preparedStepUp(true);
    // No renewal in the body, the finite choice, and the lease choice: none may leave a lease behind.
    for (const renewal of [undefined, { choice: 'finite' }, LEASED]) {
      await withNode(() => consent(id, 'approve', approval(preview, renewal)));
      expect(await leaseRows()).toEqual({ leases: 0, native: 0 });
      expect((await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).renewalLeaseCid).toBeNull();
    }
  });
}
