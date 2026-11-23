import { afterAll, beforeAll, beforeEach, expect, test } from 'bun:test';
import { Database } from 'bun:sqlite';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { serializeSignedCookie } from 'better-call';
import { parseSignedSiweCacao, pkhDid, principalDidEquals } from '@tinycloud/sdk-core';
import { admitOwnerRenewalLease } from '@tinycloud/sdk-core/delegations/renewal';
import { parseApprovalRenewal } from '@tinycloud/share-envelope/links';
import type { PrismaClient } from '@openkey/db';
import type { RenewalChoice } from '../services/renewal-lease';

const root = resolve(import.meta.dir, '../../../..');
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const nodeBinary = process.env.OPENKEY_TEST_TINYCLOUD_NODE_BINARY;

if (!process.env.OPENKEY_NATIVE_STANDING_TEST_CHILD) {
  const engines = ['pglite', ...(postgresUrl ? ['postgres'] : []), ...(nodeBinary ? ['node'] : [])];
  for (const engine of engines) {
    test(`native standing renewal through HTTP and tracked migrations (${engine})`, async () => {
      const run = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: root,
        env: {
          ...process.env, OPENKEY_NATIVE_STANDING_TEST_CHILD: engine, NODE_ENV: 'test', TEE_MODE: 'development',
          OPENKEY_RENEWAL_LEASES: 'enabled', BETTER_AUTH_URL: 'https://api.openkey.test',
          BETTER_AUTH_SECRET: 'native-renewal-test-signing-secret-0123456789',
          WEBAUTHN_RP_ID: 'openkey.test', WEBAUTHN_ORIGIN: 'https://openkey.test', CORS_ORIGIN: 'https://openkey.test',
          ADMIN_API_KEY: 'native-renewal-admin-key', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
        },
        stdout: 'pipe', stderr: 'pipe',
      });
      const [stdout, stderr, status] = await Promise.all([new Response(run.stdout).text(), new Response(run.stderr).text(), run.exited]);
      expect(status, stdout + stderr).toBe(0);
    }, 300_000);
  }
} else {
  const backend = process.env.OPENKEY_NATIVE_STANDING_TEST_CHILD;
  const postgres = backend === 'postgres';
  const realNode = backend === 'node';
  const directory = await mkdtemp('/var/tmp/openkey-native-lease-');
  const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
    .filter(entry => entry.isDirectory()).map(entry => entry.name).sort();
  const migrationSql = await Promise.all(migrations.map(name => readFile(join(root, 'packages/db/prisma/migrations', name, 'migration.sql'), 'utf8')));
  const databaseName = `native_lease_${randomUUID().replaceAll('-', '')}`;
  let admin: Client | undefined;
  if (postgres) {
    admin = new Client({ connectionString: postgresUrl });
    await admin.connect();
    await admin.query(`CREATE DATABASE "${databaseName}"`);
    const target = new URL(postgresUrl!);
    target.pathname = `/${databaseName}`;
    const connection = new Client({ connectionString: target.toString() });
    await connection.connect();
    try { for (const sql of migrationSql) await connection.query(sql); }
    finally { await connection.end(); }
    process.env.DATABASE_URL = target.toString();
  } else {
    const connection = new PGlite(directory);
    try { for (const sql of migrationSql) await connection.exec(sql); }
    finally { await connection.close(); }
    process.env.DATABASE_URL = `pglite:${directory}`;
  }
  delete process.env.OPENKEY_DATABASE_SCHEMA;

  const API = 'https://api.openkey.test';
  const ORIGIN = 'https://openkey.test';
  const ISSUER = `${API}/api/auth`;
  const CONSENT = '/api/oauth/tinycloud/requests';
  const REDIRECT = 'xyz.tinycloud.test://openkey/callback';
  const USER = 'native-lease-owner';
  const SCOPE = 'tinycloud:delegation';
  const DAY = 86_400;
  const VERIFIER = 'native-standing-lease-0123456789-0123456789-0123456789';
  const ASK = { version: 1, leaseLifetimeSeconds: 90 * DAY, purpose: 'standing' };
  const FINITE = { choice: 'finite' } as const;
  const LEASED = { choice: 'leased', leaseLifetimeSeconds: 90 * DAY } as const;
  const nodeIdentity = {
    nodeDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    renewerDid: 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp',
    renewerPublicKey: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik',
    renewerEpoch: 0,
  };
  const permissions = [
    { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
    { service: 'tinycloud.kv', space: 'applications', path: 'xyz.tinycloud.test/', actions: ['tinycloud.kv/get'] },
  ];
  let prisma: PrismaClient;
  let app: { fetch(request: Request): Response | Promise<Response> };
  let cookie: string;
  let address: string;
  let clientId: string;
  let discoveryUnavailable = false;
  let revokeUnavailable = false;
  const revoked: string[] = [];
  async function startRealNode() {
    const listener = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch: () => new Response() });
    const port = listener.port!;
    listener.stop(true);
    const origin = `http://127.0.0.1:${port}`;
    const nodeDir = await mkdtemp('/var/tmp/openkey-native-lease-node-');
    const data = join(nodeDir, 'data');
    const config = join(nodeDir, 'tinycloud.toml');
    await mkdir(data);
    await writeFile(config, [
      '[default]', 'address = "127.0.0.1"', `port = ${port}`, 'log_level = "critical"',
      '[default.storage]', `datadir = "${data}"`, `database = "sqlite:${join(data, 'caps.db')}?mode=rwc"`,
      '[default.keys]', 'type = "Static"', `secret = "${randomBytes(32).toString('base64url')}"`,
      '[default.telemetry]', 'enabled = false', '[default.epoch_head_backfill]', 'enabled = false',
    ].join('\n'), { mode: 0o600 });
    const node = Bun.spawn([nodeBinary!], {
      cwd: nodeDir, env: { PATH: '/usr/bin:/bin', TINYCLOUD_CONFIG_FILE: config, ROCKET_ADDRESS: '127.0.0.1', ROCKET_PORT: String(port) },
      stdout: 'pipe', stderr: 'pipe',
    });
    const log = Promise.all([new Response(node.stdout).text(), new Response(node.stderr).text()]);
    const stop = async () => {
      if (node.exitCode === null) node.kill();
      await node.exited;
      await rm(nodeDir, { recursive: true, force: true });
    };
    for (let attempt = 0; attempt < 60 && node.exitCode === null; attempt++) {
      try {
        const ready = await fetch(`${origin}/.well-known/tinycloud/node-keys`, { signal: AbortSignal.timeout(500) });
        if (ready.ok) return { host: origin, database: join(data, 'caps.db'), stop };
      } catch { /* Wait for loopback startup. */ }
      await Bun.sleep(100);
    }
    await stop();
    throw new Error(`Loopback renewal node failed to start: ${(await log).join('\n')}`);
  }

  const node = realNode ? null : Bun.serve({
    hostname: '127.0.0.1', port: 0,
    async fetch(request) {
      switch (new URL(request.url).pathname) {
        case '/info': return discoveryUnavailable ? new Response(null, { status: 503 }) : Response.json({ nodeId: nodeIdentity.nodeDid });
        case '/.well-known/tinycloud/node-keys': return Response.json(nodeIdentity);
        case '/delegate': return Response.json({ activated: [`tinycloud:pkh:eip155:1:${address}:applications`], skipped: [] });
        case '/revoke': {
          if (revokeUnavailable) return new Response(null, { status: 503 });
          const parsed = await parseSignedSiweCacao(request.headers.get('Authorization')!.replace(/^Bearer\s+/i, ''));
          revoked.push(parsed.audience);
          return new Response(null, { status: 204 });
        }
        default: return new Response(null, { status: 404 });
      }
    },
  });
  const runningNode = realNode ? await startRealNode() : null;
  const host = runningNode?.host ?? node!.url.origin;
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
  function par(device: ReturnType<typeof makeDevice>, renewal: unknown) {
    return form('/oauth2/par', {
      client_id: clientId, response_type: 'code', redirect_uri: REDIRECT, state: randomUUID(),
      code_challenge: hash(VERIFIER), code_challenge_method: 'S256', scope: `openid offline_access ${SCOPE}`,
      authorization_details: JSON.stringify([{ type: 'tinycloud_delegation', session_key: device.jwk, permissions, ttl_seconds: 3600, renewal }]),
    });
  }
  async function request(renewal: unknown = ASK) {
    const device = makeDevice();
    const pushed = await par(device, renewal);
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
    revision: number; digest: string; sessionSiwe: string; ttlSeconds: number; renewal?: RenewalChoice;
    hostPlan?: { hostSiwe: string } | null;
    renewalAvailable: boolean; renewalMaxLeaseLifetimeSeconds?: number; renewalPurpose?: string; renewalSensitiveConfirmationRequired?: boolean;
  }
  async function prepare(id: string, renewal?: RenewalChoice) {
    const response = await browser(`${CONSENT}/${id}/prepare`, { renewal });
    expect(response.status, await response.clone().text()).toBe(200);
    return await response.json() as Preview;
  }
  function approve(id: string, preview: Preview, renewal = preview.renewal) {
    return browser(`${CONSENT}/${id}/approve`, {
      revision: preview.revision, digest: preview.digest, sessionSiwe: preview.sessionSiwe, renewal, hostSiwe: preview.hostPlan?.hostSiwe,
    });
  }
  async function issueCode(consent: URL) {
    const accepted = await browser('/api/auth/oauth2/consent', { accept: true, oauth_query: consent.searchParams.toString() });
    expect(accepted.status, await accepted.clone().text()).toBe(200);
    const { url } = await accepted.json() as { url: string };
    const code = new URL(url).searchParams.get('code')!;
    expect(code).toBeTruthy();
    return code;
  }
  function redeemCode(device: ReturnType<typeof makeDevice>, code: string) {
    return form('/oauth2/token', { grant_type: 'authorization_code', code, client_id: clientId, redirect_uri: REDIRECT, code_verifier: VERIFIER }, device.proof(code, '/oauth2/token'));
  }
  async function exchange({ device, consent }: Awaited<ReturnType<typeof request>>) {
    return redeemCode(device, await issueCode(consent));
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
    await prisma.user.create({ data: { id: USER, email: 'native-lease@example.test', name: 'Native lease owner', emailVerified: true } });
    await prisma.session.create({ data: { id: USER, token: access, userId: USER, expiresAt: new Date(Date.now() + 3_600_000) } });
    const sealingContext = randomUUID().replaceAll('-', '').padEnd(43, 'A');
    const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    await prisma.ethereumKey.create({ data: { id: 'managed-native-lease-key', address, userId: USER, publicKey: '0x1',
      sealedBlob: await seal(key, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
    if (!realNode) await prisma.tinyCloudBootstrapState.create({ data: { userId: USER, keyId: 'managed-native-lease-key', address, chainId: 1,
      tinycloudHost: host, bootstrapVersion: 'test', status: 'complete', checkedAt: new Date(), completedAt: new Date() } });
    const response = await app.fetch(new Request(`${API}/api/admin/oauth/clients`, {
      method: 'POST', headers: { Authorization: 'Bearer native-renewal-admin-key', 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'TinyChat test', type: 'native', redirectUris: [REDIRECT], tinycloudNativeDelegation: ceiling }),
    }));
    expect(response.status, await response.clone().text()).toBe(201);
    clientId = (await response.json() as { client: { clientId: string } }).client.clientId;
  }, 30_000);

  beforeEach(async () => {
    process.env.OPENKEY_RENEWAL_LEASES = 'enabled';
    discoveryUnavailable = false;
    revokeUnavailable = false;
    revoked.length = 0;
    await prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: ceiling } });
  });

  afterAll(async () => {
    node?.stop(true);
    await runningNode?.stop();
    await prisma?.$disconnect();
    if (admin) {
      await admin.query(`DROP DATABASE "${databaseName}" WITH (FORCE)`);
      await admin.end();
    }
    await rm(directory, { recursive: true, force: true });
  });

  if (realNode) {
    test('a real node admits the consent lease for the same signed CID and settles device sign-out', async () => {
      const flow = await request();
      const preview = await prepare(flow.id, LEASED);
      expect(preview.hostPlan).toBeTruthy();
      const approved = await approve(flow.id, preview);
      expect(approved.status, await approved.clone().text()).toBe(200);
      expect(await approved.json()).toMatchObject({ hosting: 'created' });
      const token = await exchange(flow);
      expect(token.status, await token.clone().text()).toBe(200);
      const result = await token.json() as {
        renewal: unknown; refresh_token: string;
        tinycloud_delegation: {
          grantId: string; delegationCid: string; ownerDid: string; verificationMethod: string; spaceId: string;
          delegationHeader: { Authorization: string };
        };
      };
      const { receipt } = parseApprovalRenewal(result.renewal);
      const original = result.tinycloud_delegation;
      const admitted = await admitOwnerRenewalLease({
        host, originalAuthorization: original.delegationHeader.Authorization.replace(/^Bearer\s+/i, ''),
        ownerDid: original.ownerDid, agentDid: original.verificationMethod, spaceId: original.spaceId,
        originalCid: original.delegationCid, nodeIdentity: receipt.nodeIdentity, leaseCid: receipt.leaseCid,
        leaseAuthorization: receipt.leaseAuthorization, leaseExpiresAt: receipt.leaseExpiresAt,
        signal: AbortSignal.timeout(5_000),
      });
      expect(admitted).toMatchObject({ originalCid: original.delegationCid, leaseCid: receipt.leaseCid, leaseGeneration: 1 });
      const nodeDb = new Database(runningNode!.database, { readonly: true });
      try {
        expect(nodeDb.query('SELECT period_seconds, state FROM renewal_lease').get()).toEqual({ period_seconds: DAY, state: 'active' });
      } finally { nodeDb.close(); }

      const path = '/oauth2/tinycloud/revoke';
      const stopped = await form(path, { client_id: clientId, refresh_token: result.refresh_token }, flow.device.proof(result.refresh_token, path));
      expect(stopped.status, await stopped.clone().text()).toBe(200);
      expect(await prisma.renewalLease.findUnique({ where: { leaseCid: receipt.leaseCid }, include: { nativeRenewal: true } }))
        .toMatchObject({ revokedAt: expect.any(Date), nativeRenewal: { originalRevokedAt: expect.any(Date), stopRequested: false } });
    }, 30_000);
  } else {
    test('binds the request, seals the choice and hands one exact-CID lease to the device', async () => {
      const flow = await request();
      const offer = await prepare(flow.id);
      expect(offer).toMatchObject({ renewalAvailable: true, renewal: FINITE, ttlSeconds: 3600,
        renewalPurpose: 'standing', renewalMaxLeaseLifetimeSeconds: 90 * DAY, renewalSensitiveConfirmationRequired: false });
      const chosen = await prepare(flow.id, LEASED);
      expect(chosen).toMatchObject({ renewal: LEASED, ttlSeconds: DAY });
      expect(chosen.digest).not.toBe(offer.digest);
      expect((await approve(flow.id, offer)).status).toBe(409);
      expect((await approve(flow.id, chosen, FINITE)).status).toBe(409);
      expect(await prisma.renewalLease.count()).toBe(0);
      const approved = await approve(flow.id, chosen);
      expect(approved.status, await approved.clone().text()).toBe(200);
      expect(await approved.json()).not.toHaveProperty('renewal');
      expect((await approve(flow.id, chosen)).status).toBe(200);
      const held = await prisma.renewalLease.findFirstOrThrow({ include: { nativeRenewal: true } });
      expect(held.nativeRenewal).toMatchObject({ requestId: flow.id, deliveredAt: null, grantId: null });
      const token = await exchange(flow);
      expect(token.status, await token.clone().text()).toBe(200);
      const delivered = await token.json() as {
        refresh_token: string; renewal: unknown; tinycloud_delegation: { grantId: string; delegationCid: string; issuedAt: string; expiresAt: string };
      };
      const renewal = parseApprovalRenewal(delivered.renewal);
      const { receipt } = renewal;
      const original = delivered.tinycloud_delegation;
      expect(Date.parse(original.expiresAt) - Date.parse(original.issuedAt)).toBe(DAY * 1000);
      expect(renewal.approvedLeaseLifetimeSeconds).toBe(90 * DAY);
      expect(receipt).toMatchObject({ leaseCid: held.leaseCid, originalCid: original.delegationCid, nodeIdentity, leaseGeneration: 1 });
      expect(held.leaseAuthorization).not.toBe(receipt.leaseAuthorization);
      const lease = await parseSignedSiweCacao(receipt.leaseAuthorization, receipt.leaseCid);
      expect(principalDidEquals(lease.issuer, pkhDid(address, 1))).toBe(true);
      expect(lease.audience).toBe(nodeIdentity.renewerDid);
      expect(lease.attenuation).toEqual({ [`urn:cid:${original.delegationCid}`]: { 'tinycloud.delegation/renew': [{}] } });
      expect(lease.proofs).toEqual([]);
      const grant = await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: original.grantId } });
      expect(grant.renewalLeaseCid).toBe(receipt.leaseCid);
      const linked = await prisma.nativeRenewalLease.findUniqueOrThrow({ where: { leaseCid: receipt.leaseCid } });
      expect(linked).toMatchObject({ grantId: original.grantId, deliveredAt: expect.any(Date) });

      const renewPath = '/oauth2/tinycloud/renew';
      const revokePath = '/oauth2/tinycloud/revoke';
      const tokenFields = { client_id: clientId, refresh_token: delivered.refresh_token };
      const renew = await form(renewPath, tokenFields, flow.device.proof(delivered.refresh_token, renewPath));
      expect(renew.status).toBe(400);
      expect(await renew.json()).toEqual({ error: 'consent_required' });

      await prisma.oauthRefreshToken.updateMany({ where: { clientId }, data: { expiresAt: new Date(Date.now() - 60_000) } });
      await prisma.tinyCloudNativeGrant.update({ where: { id: grant.id }, data: { absoluteExpiresAt: new Date(Date.now() - 60_000) } });
      revokeUnavailable = true;
      const pending = await form(revokePath, tokenFields, flow.device.proof(delivered.refresh_token, revokePath));
      expect(pending.status).toBe(503);
      expect(await prisma.nativeRenewalLease.findUnique({ where: { leaseCid: held.leaseCid } })).toMatchObject({ stopRequested: true });
      const wrongDevice = await form(revokePath, tokenFields, makeDevice().proof(delivered.refresh_token, revokePath));
      expect(wrongDevice.status).toBe(401);
      revokeUnavailable = false;
      const stopped = await form(revokePath, tokenFields, flow.device.proof(delivered.refresh_token, revokePath));
      expect(stopped.status).toBe(200);
      expect(revoked).toEqual([`ucan:${original.delegationCid}`, `ucan:${receipt.leaseCid}`]);
      expect(await prisma.renewalLease.findUnique({ where: { leaseCid: held.leaseCid }, include: { nativeRenewal: true } }))
        .toMatchObject({ revokedAt: expect.any(Date), leaseAuthorization: null, nativeRenewal: { stopRequested: false, originalRevokedAt: expect.any(Date) } });
    });

    test('bounds the window and lets the owner choose finite after a hard setup failure', async () => {
      await prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: { ...ceiling, maxDelegationTtlSeconds: 7200, grantLifetimeSeconds: 4000 } } });
      const flow = await request({ ...ASK, purpose: 'task' });
      const offer = await prepare(flow.id);
      expect(offer).toMatchObject({ renewalPurpose: 'task', ttlSeconds: 3600, renewal: FINITE });
      const chosen = await prepare(flow.id, LEASED);
      expect(chosen.ttlSeconds).toBe(4000);
      discoveryUnavailable = true;
      const refused = await approve(flow.id, chosen);
      expect(refused.status).toBe(503);
      expect(await refused.json()).toEqual({ error: 'renewal_failed', error_description: "OpenKey couldn't set up renewal. Nothing was approved. Try again." });
      expect(await prisma.tinyCloudNativeRequest.findUnique({ where: { id: flow.id } })).toMatchObject({ status: 'RESOLVED', signature: null, renewalLeaseCid: null });
      expect(await prisma.nativeRenewalLease.findFirst({ where: { requestId: flow.id } })).toBeNull();
      const finite = await prepare(flow.id, FINITE);
      expect(finite.ttlSeconds).toBe(3600);
      const approved = await approve(flow.id, finite);
      expect(approved.status, await approved.clone().text()).toBe(200);
      const token = await exchange(flow);
      expect(token.status, await token.clone().text()).toBe(200);
      expect(await token.json()).toMatchObject({ renewal: null });
    });

    test('withdrawal queues unredeemed leases and Settings stop retains the original window', async () => {
      const { stopAllRenewalLeasesOnce } = await import('../services/renewal-lease-sweep');
      const flow = await request();
      const preview = await prepare(flow.id, LEASED);
      expect((await approve(flow.id, preview)).status).toBe(200);
      const lease = await prisma.renewalLease.findFirstOrThrow({ where: { nativeRenewal: { is: { requestId: flow.id } } } });
      const stopped = await browser(`/api/account/renewal-leases/${lease.leaseCid}/stop`, {});
      expect(stopped.status, await stopped.clone().text()).toBe(200);
      expect(revoked).toEqual([]);
      expect(await prisma.nativeRenewalLease.findUnique({ where: { leaseCid: lease.leaseCid } })).toMatchObject({ stopRequested: false, originalRevokedAt: null });

      const second = await request();
      expect((await approve(second.id, await prepare(second.id, LEASED))).status).toBe(200);
      const withdrawn = await browser(`/api/account/tinycloud-apps/${clientId}`, { confirmation: 'DISCONNECT' }, 'DELETE');
      expect(withdrawn.status, await withdrawn.clone().text()).toBe(200);
      const queued = await prisma.nativeRenewalLease.findFirstOrThrow({ where: { requestId: second.id }, include: { lease: true } });
      expect(queued).toMatchObject({ stopRequested: true, deliveredAt: null });
      const report = await stopAllRenewalLeasesOnce(prisma, undefined, undefined, true);
      expect(report.notStopped).toBe(0);
      expect(revoked).toContain(`ucan:${queued.lease.originalCid}`);
      expect(await prisma.nativeRenewalLease.findUnique({ where: { leaseCid: queued.leaseCid } })).toMatchObject({ stopRequested: false });
    });

    test('Settings stop and native code redemption serialize on the owner', async () => {
      const flow = await request();
      expect((await approve(flow.id, await prepare(flow.id, LEASED))).status).toBe(200);
      const bound = await prisma.nativeRenewalLease.findFirstOrThrow({ where: { requestId: flow.id } });
      const code = await issueCode(flow.consent);
      const [stopped, exchanged] = await Promise.all([
        browser(`/api/account/renewal-leases/${bound.leaseCid}/stop`, {}),
        redeemCode(flow.device, code),
      ]);
      expect(stopped.status, await stopped.clone().text()).toBe(200);
      const lease = await prisma.renewalLease.findUniqueOrThrow({ where: { leaseCid: bound.leaseCid }, include: { nativeRenewal: true } });
      expect(lease.leaseAuthorization).toBeNull();
      expect(revoked).not.toContain(`ucan:${lease.originalCid}`);
      if (exchanged.status === 200) {
        const result = await exchanged.json() as { renewal: unknown };
        expect(parseApprovalRenewal(result.renewal).receipt.leaseCid).toBe(bound.leaseCid);
        expect(lease.revokedAt).toBeInstanceOf(Date);
        expect(lease.nativeRenewal?.deliveredAt).toBeInstanceOf(Date);
      } else {
        expect(exchanged.status).toBe(400);
        expect(await exchanged.json()).toMatchObject({ error: 'invalid_grant' });
        expect(lease.neverAdmittedAt).toBeInstanceOf(Date);
        expect(lease.nativeRenewal?.grantId).toBeNull();
      }
    });

    test('a lease expiring before code exchange leaves the original window usable', async () => {
      const flow = await request({ ...ASK, leaseLifetimeSeconds: 1 });
      const approved = await approve(flow.id, await prepare(flow.id, { choice: 'leased', leaseLifetimeSeconds: 1 }));
      expect(approved.status, await approved.clone().text()).toBe(200);
      await Bun.sleep(1100);
      const token = await exchange(flow);
      expect(token.status, await token.clone().text()).toBe(200);
      const result = await token.json() as { renewal: unknown; tinycloud_delegation: { expiresAt: string; delegationCid: string } };
      const receipt = parseApprovalRenewal(result.renewal).receipt;
      expect(Date.parse(receipt.leaseExpiresAt)).toBeLessThan(Date.now());
      expect(Date.parse(result.tinycloud_delegation.expiresAt)).toBeGreaterThan(Date.now());
      expect(receipt.originalCid).toBe(result.tinycloud_delegation.delegationCid);
    });

    test('refuses malformed asks and loses the offer when renewal is disabled', async () => {
      const invalid = await par(makeDevice(), { ...ASK, purpose: 'other' });
      expect(invalid.status).toBe(400);
      expect(await invalid.json()).toMatchObject({ error: 'invalid_renewal_request' });
      const first = await request();
      const chosen = await prepare(first.id, LEASED);
      process.env.OPENKEY_RENEWAL_LEASES = 'stop';
      const refused = await approve(first.id, chosen);
      expect(refused.status).toBe(400);
      expect(await refused.json()).toMatchObject({ error: 'renewal_disabled' });
      const second = await request();
      const preview = await prepare(second.id);
      expect(preview).toMatchObject({ renewalAvailable: false, ttlSeconds: 3600 });
      expect(preview).not.toHaveProperty('renewal');
    });
  }
}
