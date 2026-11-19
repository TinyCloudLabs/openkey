// TC-3088 on a real tinycloud-node (opt-in): the stop sweep (`OPENKEY_RENEWAL_LEASES=stop`) stops every OpenKey-signed
// lease after the node has actually renewed each grant, and the node then renews them no more; a wallet-signed lease
// is left on and keeps renewing. The OpenKey API runs whole on PGlite; the node is a real binary on loopback with a
// private home and data dir. Same harness as renewal-lease-stop.real-node.test.ts.
//
//   OPENKEY_TEST_TINYCLOUD_NODE_BINARY=/path/to/tinycloud bun test apps/api/src/__tests__/renewal-lease-sweep.real-node.test.ts
//
// About 18 minutes: the node's scheduler renews at an original's half-life and runs every 5 minutes, so the
// originals last 16 minutes, and the reads that tell a stopped lease from a live one happen after they end.
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomBytes, randomUUID } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import { closeSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Database } from 'bun:sqlite';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
const nodeBinary = process.env.OPENKEY_TEST_TINYCLOUD_NODE_BINARY;
const ORIGINAL_MS = 16 * 60_000;
const LEASE_SECONDS = 40 * 60;
const ORIGIN = 'https://openkey.test';

if (process.env.OPENKEY_RENEWAL_STOP_TEST_CHILD !== '1') {
  test.skipIf(!nodeBinary)('the stop sweep stops every OpenKey-signed lease on a real node, which then renews them no more', async () => {
    const home = mkdtempSync(join(tmpdir(), 'openkey-renewal-stop-home-'));
    try {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: root,
        env: {
          PATH: process.env.PATH,
          HOME: home,
          TC_HOME: home,
          OPENKEY_RENEWAL_STOP_TEST_CHILD: '1',
          OPENKEY_TEST_TINYCLOUD_NODE_BINARY: nodeBinary,
          NODE_ENV: 'test',
          TEE_MODE: 'development',
          BETTER_AUTH_URL: 'https://api.openkey.test',
          BETTER_AUTH_SECRET: 'renewal-lease-stop-isolated-test-secret',
          WEBAUTHN_RP_ID: 'openkey.test',
          WEBAUTHN_ORIGIN: ORIGIN,
          CORS_ORIGIN: ORIGIN,
          RESEND_API_KEY: '',
          GOOGLE_CLIENT_ID: '',
          GOOGLE_CLIENT_SECRET: '',
        },
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect(exitCode, stdout + stderr).toBe(0);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }, 30 * 60_000);
} else {
  let directory: string;
  let nodeDir: string;
  let node: ChildProcess;
  let registry: Server;
  let host: string;
  let registryOrigin: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookieName: string;
  let secret: string;

  async function freePort(): Promise<number> {
    const server = createServer();
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const { port } = server.address() as { port: number };
    server.close();
    await once(server, 'close');
    return port;
  }

  beforeAll(async () => {
    nodeDir = mkdtempSync(join(tmpdir(), 'openkey-renewal-stop-node-'));
    const dataDir = join(nodeDir, 'data');
    mkdirSync(dataDir, { mode: 0o700 });
    const port = await freePort();
    host = `http://127.0.0.1:${port}`;
    registry = createServer((_request, response) => {
      response.writeHead(404, { 'content-type': 'application/json' });
      response.end('{"error":"location record not found"}');
    });
    registry.listen(0, '127.0.0.1');
    await once(registry, 'listening');
    registryOrigin = `http://127.0.0.1:${(registry.address() as { port: number }).port}`;
    const config = join(nodeDir, 'tinycloud.toml');
    writeFileSync(config, [
      '[default]', 'address = "127.0.0.1"', `port = ${port}`, 'log_level = "critical"', '',
      '[default.storage]', `datadir = ${JSON.stringify(dataDir)}`, `database = ${JSON.stringify(`sqlite:${join(dataDir, 'caps.db')}?mode=rwc`)}`, '',
      '[default.keys]', 'type = "Static"', `secret = ${JSON.stringify(randomBytes(32).toString('base64url'))}`, '',
      '[default.telemetry]', 'enabled = false', '', '[default.epoch_head_backfill]', 'enabled = false', '',
    ].join('\n'), { mode: 0o600 });
    const log = openSync(join(nodeDir, 'node.log'), 'a', 0o600);
    node = spawn(nodeBinary!, [], {
      cwd: nodeDir,
      env: { PATH: '/usr/bin:/bin', HOME: process.env.HOME, TC_HOME: process.env.HOME, TINYCLOUD_CONFIG_FILE: config, ROCKET_ADDRESS: '127.0.0.1', ROCKET_PORT: String(port) },
      stdio: ['ignore', log, log],
    });
    closeSync(log);
    for (let attempt = 0; attempt < 120; attempt++) {
      try { if ((await fetch(`${host}/.well-known/tinycloud/node-keys`)).ok) break; } catch { /* not up yet */ }
      await delay(250);
    }

    directory = mkdtempSync(join(tmpdir(), 'openkey-renewal-stop-db-'));
    const database = new PGlite(directory);
    try {
      const migrations = readdirSync(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true })
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) {
        await database.exec(readFileSync(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
    } finally {
      await database.close();
    }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    const context = await authModule.auth.$context;
    cookieName = context.authCookies.sessionToken.name;
    secret = context.secret;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    node?.kill('SIGCONT');
    node?.kill('SIGTERM');
    if (node) await Promise.race([once(node, 'exit'), delay(10_000)]);
    registry?.close();
    if (directory) rmSync(directory, { recursive: true, force: true });
    if (nodeDir) rmSync(nodeDir, { recursive: true, force: true });
  });

  /** Renewal stamps the node admitted for the lease `owner` granted (lease CIDs are stored as bytes; the grantor is the owner DID). */
  function stamps(owner: string): number {
    const db = new Database(join(nodeDir, 'data', 'caps.db'), { readonly: true });
    try {
      return (db.prepare(`SELECT count(*) AS n FROM renewal_stamp s JOIN renewal_lease l ON l.lease_cid = s.lease_cid
        WHERE lower(l.grantor) LIKE '%' || lower(?)`).get(owner) as { n: number }).n;
    } finally { db.close(); }
  }

  /**
   * An OpenKey account whose managed key approved one renewal, recorded the way the approval records it: reserved
   * before admission, then confirmed once the approval is saved. `unconfirmed`: admitted, but the approval was
   * never saved (a crash after admission). `unadmitted`: reserved and signed, but the node was never asked.
   */
  async function ownerWithLease(label: string, mode: 'confirmed' | 'unconfirmed' | 'unadmitted' = 'confirmed', external = false) {
    // Imported here, after beforeAll set DATABASE_URL: the API modules open their database when loaded.
    const { TinyCloudNode } = await import('@tinycloud/node-sdk');
    const { privateKeyToAccount } = await import('viem/accounts');
    const { createTeeClient, seal } = await import('@openkey/tee');
    const { createSealingContext } = await import('../services/key-sealing');
    const { prepareRenewalStage, signLease, admitLease } = await import('../services/renewal-lease');
    const { reserveRenewalLease } = await import('../services/renewal-lease-revocation');
    const userId = `renewal-${label}-${randomUUID()}`;
    const privateKey = `0x${randomBytes(32).toString('hex')}` as const;
    const account = privateKeyToAccount(privateKey);
    const sealingContext = createSealingContext();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: label, emailVerified: true } });
    // `external`: a wallet OpenKey doesn't hold signed this lease. The key row has no sealed blob, so only the
    // wallet can revoke it; the test still signs with the private key it generated.
    await prisma.ethereumKey.create({ data: external ? {
      userId, address: account.address, publicKey: account.address, keyIndex: 0, isCanonicalTinyCloud: true, keyType: 'EXTERNAL',
    } : {
      userId, address: account.address, publicKey: account.address, keyIndex: 0, isCanonicalTinyCloud: true, sealingContext,
      sealedBlob: await seal(privateKey, await createTeeClient().deriveKey(`openkey/key/${sealingContext}`)),
    } });
    const token = randomUUID();
    const sessionId = randomUUID();
    await prisma.session.create({ data: { id: sessionId, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;

    const client = new TinyCloudNode({ privateKey: privateKey.slice(2), host, tinycloudRegistryUrl: registryOrigin, newUserHost: host, autoCreateSpace: true,
      autoBootstrapAccount: false, includeAccountRegistryPermissions: false, autoDiscoverLocalNode: false, sessionExpirationMs: ORIGINAL_MS,
      retryPolicy: { maxAttempts: 1 } } as never);
    await client.signIn();
    await client.kv.put(`proof-${label}`, label);
    const session = client.restorableSession as unknown as { delegationHeader: { Authorization: string }; delegationCid: string; spaceId: string; siwe: string; jwk: { kty: 'OKP'; crv: 'Ed25519'; x: string } };
    const delegation = { delegationHeader: session.delegationHeader, delegationCid: session.delegationCid, spaceId: session.spaceId, siwe: session.siwe, hostActivated: true };
    let stage = await prepareRenewalStage({ userId, host, leaseLifetimeSeconds: LEASE_SECONDS, delegation, now: new Date() });
    stage = signLease(stage, await account.signMessage({ message: stage.leaseSiwe }));
    const approvalRequestId = randomBytes(16).toString('hex');
    await prisma.approvalRequest.create({ data: {
      id: approvalRequestId, bodyCid: 'body', issuer: 'did:key:requester', expiresAt: new Date(Date.now() + 600_000),
      request: { reason: `Keep ${label}'s notes in sync`, permissions: [{ service: 'tinycloud.kv', space: session.spaceId, path: '', actions: ['tinycloud.kv/get'] }] },
    } });
    await reserveRenewalLease(prisma, { approvalRequestId, userId, sessionId, nodeOrigin: host, stage });
    if (mode !== 'unadmitted') await admitLease(stage, { nodeOrigin: host, targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: session.jwk.x } });
    if (mode === 'confirmed') await prisma.renewalLease.update({ where: { leaseCid: stage.leaseCid! }, data: { admittedAt: new Date(), leaseAuthorization: null } });
    const originalEnd = Date.parse(/^Expiration Time: (.+)$/m.exec(session.siwe)![1]!);
    return { userId, sessionId, cookie, client, address: account.address, leaseCid: stage.leaseCid!, leaseAuthorization: stage.leaseAuthorization!, originalEnd, label };
  }

  const call = (cookie: string, path: string, method: 'GET' | 'POST', body?: unknown) => app.fetch(new Request(`https://api.openkey.test${path}`, {
    method, headers: { cookie, origin: ORIGIN, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));

  async function reads(owner: Awaited<ReturnType<typeof ownerWithLease>>): Promise<boolean> {
    try {
      const result = await owner.client.kv.get(`proof-${owner.label}`) as unknown as { ok?: boolean };
      return result?.ok === true;
    } catch {
      return false;
    }
  }

  const revokedAt = async (leaseCid: string) => (await prisma.renewalLease.findUnique({ where: { leaseCid } }))?.revokedAt ?? null;

  test('the stop sweep stops every OpenKey-signed lease the node has renewed, and the node renews them no more; a wallet-signed lease is left on', async () => {
    const { renewalLeaseReport } = await import('../services/renewal-lease-report');
    const { stopAllRenewalLeasesOnce } = await import('../services/renewal-lease-sweep');
    const sweptA = await ownerWithLease('swept-a');
    const sweptB = await ownerWithLease('swept-b');
    // Signed by a wallet OpenKey doesn't hold: the sweep can't revoke it, so the node keeps renewing it.
    const wallet = await ownerWithLease('wallet', 'confirmed', true);
    const owners = [sweptA, sweptB, wallet];

    // Wait for the node's own renewal of every grant.
    while (owners.some((owner) => stamps(owner.address) === 0)) {
      if (Date.now() > Math.min(...owners.map((owner) => owner.originalEnd)) - 30_000) throw new Error('the node did not renew every grant in time');
      await delay(10_000);
    }
    expect(await reads(sweptA)).toBe(true);
    expect(await reads(sweptB)).toBe(true);

    // The operator's count first, then the kill.
    expect(await renewalLeaseReport(prisma)).toMatchObject({ live: 3, openkeySigned: 2, walletSigned: 1, unconfirmed: 0, accounts: 3 });
    expect(await stopAllRenewalLeasesOnce(prisma)).toEqual({ users: 3, stopped: 2, walletRequired: 1, notStopped: 0 });
    expect(await revokedAt(sweptA.leaseCid)).not.toBeNull();
    expect(await revokedAt(sweptB.leaseCid)).not.toBeNull();
    expect(await revokedAt(wallet.leaseCid)).toBeNull();
    // Run again: nothing left for OpenKey to stop; the wallet-signed lease is still reported.
    expect(await stopAllRenewalLeasesOnce(prisma)).toEqual({ users: 1, stopped: 0, walletRequired: 1, notStopped: 0 });
    expect(await renewalLeaseReport(prisma)).toMatchObject({ live: 1, openkeySigned: 0, walletSigned: 1, accounts: 1 });

    // The node stamped each of these grants once before the stop; it adds none after it.
    const stampsAtStop = { a: stamps(sweptA.address), b: stamps(sweptB.address), wallet: stamps(wallet.address) };
    expect(stampsAtStop.a).toBeGreaterThan(0);

    // Past every original's signed end: the stopped grants lapse at that end (the node renews them no more),
    // the wallet-signed grant lives on renewed time.
    const latestEnd = Math.max(...owners.map((owner) => owner.originalEnd));
    while (Date.now() < latestEnd + 30_000) await delay(5_000);
    expect(await reads(sweptA)).toBe(false);
    expect(await reads(sweptB)).toBe(false);
    expect(await reads(wallet)).toBe(true);
    expect(stamps(sweptA.address)).toBe(stampsAtStop.a);
    expect(stamps(sweptB.address)).toBe(stampsAtStop.b);
  }, 28 * 60_000);
}
