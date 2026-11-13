// TC-2946: which leases each owner action stops, and what is reported, through the whole API (routes, Better
// Auth hooks, managed-key signing). The node is a loopback stand-in that answers `/revoke` and `/delegate`; the
// real node's acceptance of these revocations is covered by renewal-lease-stop.real-node.test.ts. Runs on PGlite,
// and also on Postgres when OPENKEY_TEST_POSTGRES_URL is set, where the concurrency cases run too.
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { serializeSignedCookie } from 'better-call';
import { symmetricEncrypt } from 'better-auth/crypto';
import type { PrismaClient } from '@openkey/db';
import { mockModules } from './mock-module';

const root = resolve(import.meta.dir, '../../../..');
const ORIGIN = 'https://openkey.test';
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const backend = process.env.OPENKEY_RENEWAL_STOP_BACKEND === 'postgres' ? 'postgres' : 'pglite';

if (process.env.OPENKEY_RENEWAL_STOP_CI_CHILD !== '1') {
  for (const engine of ['pglite', 'postgres'] as const) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(`renewal leases: dashboard stop, sign-out scopes, deletion and wallet stops (${engine})`, async () => {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: root,
        env: {
          ...process.env,
          OPENKEY_RENEWAL_STOP_CI_CHILD: '1',
          OPENKEY_RENEWAL_STOP_BACKEND: engine,
          NODE_ENV: 'test',
          TEE_MODE: 'development',
          BETTER_AUTH_URL: 'https://api.openkey.test',
          BETTER_AUTH_SECRET: 'renewal-lease-stop-ci-isolated-test-secret',
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
    }, 300_000);
  }
} else {
  let directory: string | undefined;
  let admin: Client | undefined;
  const databaseName = `renewal_stop_${randomBytes(6).toString('hex')}`;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookieName: string;
  let secret: string;
  let secretConfig: Parameters<typeof symmetricEncrypt>[0]['key'];
  // A stand-in node per behaviour. `ok` confirms every admission and revocation; `down` fails until it is switched
  // on; `gone` refuses both, answering a revocation with the node's own "not present" refusal (it never admitted the
  // lease and won't); `cdn` refuses both with a bare 403 page, as a proxy in front of a node would; `slow` answers
  // after `delayMs`. Each records the paths it was asked, in order; `onCall` runs before it answers.
  type NodeName = 'ok' | 'down' | 'gone' | 'cdn' | 'slow';
  type Node = { server: Server; origin: string; up: boolean; revocations: number; calls: string[]; delayMs: number; onCall?: (path: string) => Promise<void> };
  const nodes: Record<NodeName, Node> = {} as never;

  // The database exists before any API module loads: they open it when loaded.
  const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  if (backend === 'postgres') {
    admin = new Client({ connectionString: postgresUrl });
    await admin.connect();
    await admin.query(`CREATE DATABASE "${databaseName}"`);
    const target = new URL(postgresUrl!);
    target.pathname = `/${databaseName}`;
    const migrationConnection = new Client({ connectionString: target.toString() });
    await migrationConnection.connect();
    try {
      for (const migration of migrations) await migrationConnection.query(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    } finally { await migrationConnection.end(); }
    process.env.DATABASE_URL = target.toString();
  } else {
    directory = await mkdtemp(join(tmpdir(), 'openkey-renewal-stop-'));
    const database = new PGlite(directory);
    try {
      for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    } finally { await database.close(); }
    process.env.DATABASE_URL = `pglite:${directory}`;
  }
  delete process.env.OPENKEY_DATABASE_SCHEMA;

  // Runs once, right after the next revoke pass returns: account deletion's pass, before its locked transaction.
  let afterRevokePass: (() => Promise<void>) | undefined;
  await mockModules({
    '../services/renewal-lease-revocation': (actual) => ({
      revokeRenewalLeases: async (...args: unknown[]) => {
        const report = await actual.revokeRenewalLeases(...args);
        const hook = afterRevokePass;
        afterRevokePass = undefined;
        if (hook) await hook();
        return report;
      },
    }),
  });

  beforeAll(async () => {
    for (const name of ['ok', 'down', 'gone', 'cdn', 'slow'] as const) {
      const node: Node = { server: createServer(), origin: '', up: name === 'ok' || name === 'slow', revocations: 0, calls: [], delayMs: 0 };
      node.server.on('request', async (request, response) => {
        const signed = request.method === 'POST' && (request.url === '/revoke' || request.url === '/delegate') && typeof request.headers.authorization === 'string';
        if (signed) node.calls.push(request.url!);
        if (signed && request.url === '/revoke') node.revocations++;
        if (signed && node.onCall) await node.onCall(request.url!);
        if (node.delayMs) await delay(node.delayMs);
        if (response.destroyed) return;
        if (!signed) { response.writeHead(404); response.end(); return; }
        if (node.up) { response.writeHead(200, { 'content-type': 'application/json' }); response.end('{}'); return; }
        if (name === 'gone') {
          response.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
          response.end(request.url === '/revoke' ? 'Cannot find parent delegation' : 'Delegation refused');
          return;
        }
        if (name === 'cdn') { response.writeHead(403, { 'content-type': 'text/html' }); response.end('<html><body>403 Forbidden</body></html>'); return; }
        response.writeHead(503, { 'content-type': 'application/json' });
        response.end('{"error":"no"}');
      });
      node.server.listen(0, '127.0.0.1');
      await once(node.server, 'listening');
      node.origin = `http://127.0.0.1:${(node.server.address() as { port: number }).port}`;
      nodes[name] = node;
    }
    // Loaded after DATABASE_URL is set: the API modules open their database when loaded.
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    const context = await authModule.auth.$context;
    cookieName = context.authCookies.sessionToken.name;
    secret = context.secret;
    secretConfig = context.secretConfig;
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    for (const node of Object.values(nodes)) node.server.close();
    if (directory) await rm(directory, { recursive: true, force: true });
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`).catch(() => undefined);
      await admin.end();
    }
  });

  async function account(keyType: 'MANAGED' | 'EXTERNAL' = 'MANAGED') {
    const { createTeeClient, seal } = await import('@openkey/tee');
    const { privateKeyToAccount } = await import('viem/accounts');
    const { createSealingContext } = await import('../services/key-sealing');
    const userId = `renewal-${randomUUID()}`;
    const privateKey = `0x${randomBytes(32).toString('hex')}` as const;
    const wallet = privateKeyToAccount(privateKey);
    const sealingContext = createSealingContext();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    await prisma.ethereumKey.create({ data: {
      userId, address: wallet.address, publicKey: wallet.address, keyIndex: 0, keyType, sealingContext: keyType === 'MANAGED' ? sealingContext : null,
      sealedBlob: keyType === 'MANAGED' ? await seal(privateKey, await createTeeClient().deriveKey(`openkey/key/${sealingContext}`)) : null,
    } });
    const session = async () => {
      const token = randomUUID();
      const id = randomUUID();
      await prisma.session.create({ data: { id, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
      return { id, token, cookie: (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]! };
    };
    return { userId, wallet, session };
  }

  let leaseCount = 0;
  /** `reserved`: recorded before admission and never confirmed, holding its encrypted signed lease. */
  async function lease(owner: Awaited<ReturnType<typeof account>>, sessionId: string | null, node: NodeName = 'ok', expiresInMs = 3_600_000, reserved = false) {
    const leaseCid = `bafkr4i${(leaseCount++).toString().padStart(4, '0').replace(/\d/g, (d) => 'abcdefghij'[Number(d)]!)}${'a'.repeat(48)}`;
    const approvalRequestId = randomBytes(16).toString('hex');
    await prisma.approvalRequest.create({ data: {
      id: approvalRequestId, bodyCid: 'body', issuer: 'did:key:requester', expiresAt: new Date(Date.now() + 600_000),
      request: { reason: 'Keep notes in sync', permissions: [{ service: 'tinycloud.kv', space: 'space', path: 'notes/', actions: ['tinycloud.kv/get'] }] },
    } });
    await prisma.renewalLease.create({ data: {
      leaseCid, userId: owner.userId, sessionId, approvalRequestId, ownerDid: `did:pkh:eip155:1:${owner.wallet.address}`,
      originalCid: `bafkr4ioriginal${'a'.repeat(44)}`, nodeOrigin: nodes[node].origin, nodeDid: 'did:key:node', renewerDid: 'did:key:renewer',
      leaseLifetimeSeconds: 3600, approvedAt: new Date(), leaseExpiresAt: new Date(Date.now() + expiresInMs), grantSiwe: 'the approved grant',
      ...(reserved
        ? { admittedAt: null, leaseAuthorization: await symmetricEncrypt({ key: secretConfig, data: `signed-lease-${leaseCid}` }) }
        : { admittedAt: new Date() }),
    } });
    return leaseCid;
  }

  const call = (cookie: string, path: string, method: 'GET' | 'POST', body?: unknown) => app.fetch(new Request(`https://api.openkey.test${path}`, {
    method, headers: { cookie, origin: ORIGIN, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
  const stopped = async (leaseCid: string) => (await prisma.renewalLease.findUnique({ where: { leaseCid } }))?.revokedAt != null;

  test('the dashboard lists only the account\'s live leases and stops exactly the one named; others get 404', async () => {
    const owner = await account();
    const { cookie } = await owner.session();
    const first = await lease(owner, null);
    const second = await lease(owner, null);
    await lease(owner, null, 'ok', -1_000);
    const stranger = await account();
    const strangerSession = await stranger.session();

    const listed = await (await call(cookie, '/api/account/renewal-leases', 'GET')).json() as { leases: Array<{ leaseCid: string; signer: string }> };
    expect(listed.leases.map((row) => row.leaseCid).sort()).toEqual([first, second].sort());
    expect(listed.leases.every((row) => row.signer === 'openkey')).toBe(true);
    expect((await (await call(strangerSession.cookie, '/api/account/renewal-leases', 'GET')).json() as { leases: unknown[] }).leases).toEqual([]);
    expect((await call(strangerSession.cookie, `/api/account/renewal-leases/${first}/stop`, 'POST', {})).status).toBe(404);
    expect(await stopped(first)).toBe(false);

    expect((await call(cookie, `/api/account/renewal-leases/${first}/stop`, 'POST', {})).status).toBe(200);
    expect(await stopped(first)).toBe(true);
    expect(await stopped(second)).toBe(false);
    expect((await call(cookie, `/api/account/renewal-leases/${first}/stop`, 'POST', {})).status).toBe(404);
  });

  test('a node that does not confirm leaves the lease on; the retry stops it', async () => {
    const owner = await account();
    const { cookie } = await owner.session();
    const leaseCid = await lease(owner, null, 'down');
    const refused = await call(cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', {});
    expect(refused.status).toBe(503);
    expect(await stopped(leaseCid)).toBe(false);
    nodes.down.up = true;
    try {
      expect((await call(cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', {})).status).toBe(200);
    } finally {
      nodes.down.up = false;
    }
    expect(await stopped(leaseCid)).toBe(true);
  });

  test('a wallet-signed lease is stopped only with that wallet\'s signature on the prepared message', async () => {
    const owner = await account('EXTERNAL');
    const { cookie } = await owner.session();
    const leaseCid = await lease(owner, null);
    const prepared = await call(cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', {});
    expect(prepared.status).toBe(409);
    const { siwe, code } = await prepared.json() as { siwe: string; code: string };
    expect(code).toBe('wallet_required');
    expect(siwe).toContain(`URI: ucan:${leaseCid}`);

    const other = await account('EXTERNAL');
    const otherLease = await lease(owner, null);
    const wrongSigner = await call(cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', { siwe, signature: await other.wallet.signMessage({ message: siwe }) });
    expect(wrongSigner.status).toBe(400);
    const wrongLease = await call(cookie, `/api/account/renewal-leases/${otherLease}/stop`, 'POST', { siwe, signature: await owner.wallet.signMessage({ message: siwe }) });
    expect(wrongLease.status).toBe(400);
    expect(await stopped(leaseCid)).toBe(false);

    const signed = await call(cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', { siwe, signature: await owner.wallet.signMessage({ message: siwe }) });
    expect(signed.status).toBe(200);
    expect(await stopped(leaseCid)).toBe(true);
    expect(await stopped(otherLease)).toBe(false);
  });

  test('signing out stops this session\'s leases; other sessions stops all but this one\'s; everywhere stops all', async () => {
    const owner = await account();
    const [here, there, elsewhere] = [await owner.session(), await owner.session(), await owner.session()];
    const hereLease = await lease(owner, here.id);
    const thereLease = await lease(owner, there.id);
    const orphanLease = await lease(owner, randomUUID());
    const elsewhereLease = await lease(owner, elsewhere.id);

    const others = await call(here.cookie, '/api/auth/revoke-other-sessions', 'POST');
    expect(others.status).toBe(200);
    expect(await others.json()).toEqual({ status: true, renewalLeases: { stopped: 3, notStopped: 0, walletRequired: 0 } });
    expect([await stopped(hereLease), await stopped(thereLease), await stopped(orphanLease), await stopped(elsewhereLease)]).toEqual([false, true, true, true]);

    const signedOut = await call(here.cookie, '/api/auth/sign-out', 'POST');
    expect(signedOut.status).toBe(200);
    expect(await signedOut.json()).toMatchObject({ success: true, renewalLeases: { stopped: 1, notStopped: 0 } });
    expect(await stopped(hereLease)).toBe(true);

    // Signing out one named session stops only its leases.
    const second = await account();
    const [one, two] = [await second.session(), await second.session()];
    const oneLease = await lease(second, one.id);
    const twoLease = await lease(second, two.id);
    const named = await call(one.cookie, '/api/auth/revoke-session', 'POST', { token: two.token });
    expect(named.status).toBe(200);
    expect([await stopped(oneLease), await stopped(twoLease)]).toEqual([false, true]);

    const third = await account();
    const three = await third.session();
    const leases = [await lease(third, three.id), await lease(third, (await third.session()).id), await lease(third, null)];
    const everywhere = await call(three.cookie, '/api/auth/revoke-sessions', 'POST');
    expect(everywhere.status).toBe(200);
    expect(await Promise.all(leases.map(stopped))).toEqual([true, true, true]);
  });

  test('sign-out goes ahead when a lease stays on, and says so; a sign-out with no leases answers as before', async () => {
    const owner = await account();
    const here = await owner.session();
    const leaseCid = await lease(owner, here.id, 'down');
    const signedOut = await call(here.cookie, '/api/auth/sign-out', 'POST');
    expect(signedOut.status).toBe(200);
    expect(await signedOut.json()).toMatchObject({ success: true, renewalLeases: { stopped: 0, notStopped: 1, walletRequired: 0 } });
    expect(await prisma.session.count({ where: { id: here.id } })).toBe(0);
    expect(await stopped(leaseCid)).toBe(false);

    const plain = await (await account()).session();
    const quiet = await call(plain.cookie, '/api/auth/sign-out', 'POST');
    expect(await quiet.json()).toEqual({ success: true });
  });

  test('deletion stops every lease first; until every one is confirmed nothing is deleted', async () => {
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const owner = await account();
    const here = await owner.session();
    const confirmed = await lease(owner, here.id);
    const pending = await lease(owner, null, 'down');
    await writeStepUpMarker(prisma, 'delete_account', here.id, 'email');

    const refused = await call(here.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' });
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ code: 'renewal_leases_not_stopped', nodeUnavailable: 1, walletRequired: 0 });
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
    expect(await prisma.ethereumKey.count({ where: { userId: owner.userId } })).toBe(1);
    expect([await stopped(confirmed), await stopped(pending)]).toEqual([true, false]);

    nodes.down.up = true;
    const revocationsBefore = nodes.ok.revocations;
    try {
      const deleted = await call(here.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' });
      expect(deleted.status).toBe(200);
    } finally {
      nodes.down.up = false;
    }
    // The confirmed lease is not sent again.
    expect(nodes.ok.revocations).toBe(revocationsBefore);
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
  });

  test('deletion is refused while a wallet-signed lease renews', async () => {
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const owner = await account('EXTERNAL');
    const here = await owner.session();
    await lease(owner, null);
    await writeStepUpMarker(prisma, 'delete_account', here.id, 'email');
    const refused = await call(here.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' });
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ code: 'renewal_leases_not_stopped', walletRequired: 1 });
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
  });

  test('a lease whose admission was never confirmed is admitted again and revoked straight after; one admitted is only revoked', async () => {
    const owner = await account();
    const { cookie } = await owner.session();
    const reserved = await lease(owner, null, 'ok', 3_600_000, true);
    const admitted = await lease(owner, null);
    nodes.ok.calls.length = 0;
    expect((await call(cookie, `/api/account/renewal-leases/${reserved}/stop`, 'POST', {})).status).toBe(200);
    expect(nodes.ok.calls).toEqual(['/delegate', '/revoke']);
    const row = await prisma.renewalLease.findUniqueOrThrow({ where: { leaseCid: reserved } });
    expect(row.revokedAt).not.toBeNull();
    // The signed lease is kept only until its lease is settled.
    expect(row.leaseAuthorization).toBeNull();
    nodes.ok.calls.length = 0;
    expect((await call(cookie, `/api/account/renewal-leases/${admitted}/stop`, 'POST', {})).status).toBe(200);
    expect(nodes.ok.calls).toEqual(['/revoke']);
  });

  test('a lease the node refuses to admit and has nothing to revoke is settled as never admitted, and never reserved again', async () => {
    const { reserveRenewalLease } = await import('../services/renewal-lease-revocation');
    const owner = await account();
    const { cookie } = await owner.session();
    const leaseCid = await lease(owner, null, 'gone', 3_600_000, true);
    expect((await call(cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', {})).status).toBe(200);
    const row = await prisma.renewalLease.findUniqueOrThrow({ where: { leaseCid } });
    expect([row.neverAdmittedAt !== null, row.revokedAt, row.leaseAuthorization]).toEqual([true, null, null]);
    expect((await (await call(cookie, '/api/account/renewal-leases', 'GET')).json() as { leases: unknown[] }).leases).toEqual([]);
    // A stalled approval of that same lease finds it settled: it is not admitted.
    const stage = {
      leaseCid, leaseAuthorization: 'signed-lease', delegation: { siwe: 'grant' }, chainId: 1, ownerAddress: owner.wallet.address,
      originalCid: row.originalCid, nodeIdentity: { nodeDid: 'did:key:node', renewerDid: 'did:key:renewer' }, approvedLeaseLifetimeSeconds: 3600,
      approvedAt: new Date().toISOString(), leaseExpiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    };
    await expect(reserveRenewalLease(prisma, { approvalRequestId: row.approvalRequestId, userId: owner.userId, sessionId: null, nodeOrigin: row.nodeOrigin, stage: stage as never }))
      .rejects.toMatchObject({ code: 'renewal_stopped' });
  });

  test('a stored signed lease that no longer decrypts is not replayed but still revoked; never called never admitted; blocks deletion', async () => {
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const owner = await account();
    const here = await owner.session();
    const leaseCid = await lease(owner, here.id, 'gone', 3_600_000, true);
    // As if the at-rest secret had been rotated since it was stored.
    await prisma.renewalLease.update({ where: { leaseCid }, data: { leaseAuthorization: 'sealed-with-an-old-secret' } });
    nodes.gone.calls.length = 0;
    expect((await call(here.cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', {})).status).toBe(503);
    // Nothing to replay, so the node's "not present" can't show it was never admitted.
    expect(nodes.gone.calls).toEqual(['/revoke']);
    const row = await prisma.renewalLease.findUniqueOrThrow({ where: { leaseCid } });
    expect([row.revokedAt, row.neverAdmittedAt, row.leaseAuthorization]).toEqual([null, null, 'sealed-with-an-old-secret']);
    await writeStepUpMarker(prisma, 'delete_account', here.id, 'email');
    const refused = await call(here.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' });
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ code: 'renewal_leases_not_stopped', nodeUnavailable: 1 });
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
  });

  test('deletion during an approval whose lease is admitted but not yet saved: the reservation blocks it until the lease is settled', async () => {
    // The approval reserves its lease before asking the node to admit it; the node admitted it and the approval
    // has not saved yet (or crashed). Deletion must find that lease, not only saved ones.
    const { reserveRenewalLease } = await import('../services/renewal-lease-revocation');
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const owner = await account();
    const here = await owner.session();
    const leaseCid = `bafkr4iinflight${'a'.repeat(45)}`;
    const approvalRequestId = randomBytes(16).toString('hex');
    const stage = {
      leaseCid, leaseAuthorization: 'signed-lease', delegation: { siwe: 'the approved grant' }, chainId: 1, ownerAddress: owner.wallet.address,
      originalCid: `bafkr4ioriginal${'a'.repeat(44)}`, nodeIdentity: { nodeDid: 'did:key:node', renewerDid: 'did:key:renewer' },
      approvedLeaseLifetimeSeconds: 3600, approvedAt: new Date().toISOString(), leaseExpiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    };
    await reserveRenewalLease(prisma, { approvalRequestId, userId: owner.userId, sessionId: here.id, nodeOrigin: nodes.down.origin, stage: stage as never });

    await writeStepUpMarker(prisma, 'delete_account', here.id, 'email');
    const refused = await call(here.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' });
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ code: 'renewal_leases_not_stopped', nodeUnavailable: 1 });
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
    expect(await prisma.ethereumKey.count({ where: { userId: owner.userId } })).toBe(1);

    nodes.down.up = true;
    nodes.down.calls.length = 0;
    try {
      expect((await call(here.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' })).status).toBe(200);
    } finally {
      nodes.down.up = false;
    }
    // Admitted again and revoked straight after, before the keys and the user went.
    expect(nodes.down.calls).toEqual(['/delegate', '/revoke']);
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
  });

  test('sign-out ends the session even when stopping its leases fails, and the leases stay on for the next attempt', async () => {
    const owner = await account();
    const here = await owner.session();
    const leaseCid = await lease(owner, here.id);
    // Break the key lookup that stopping a lease needs, as a database failure would.
    await prisma.$executeRawUnsafe('ALTER TABLE "ethereum_keys" RENAME COLUMN "address" TO "address_unavailable"');
    let signedOut: Response;
    try {
      signedOut = await call(here.cookie, '/api/auth/sign-out', 'POST');
    } finally {
      await prisma.$executeRawUnsafe('ALTER TABLE "ethereum_keys" RENAME COLUMN "address_unavailable" TO "address"');
    }
    expect(signedOut.status).toBe(200);
    expect(await signedOut.json()).toMatchObject({ success: true, renewalLeases: { stopped: 0, notStopped: 1 } });
    expect(await prisma.session.count({ where: { id: here.id } })).toBe(0);
    expect(await stopped(leaseCid)).toBe(false);
  });

  test('sign-out answers within its budget while a slow node is still being asked; stopping finishes afterwards', async () => {
    const owner = await account();
    const here = await owner.session();
    const leaseCid = await lease(owner, here.id, 'slow', 3_600_000, true);
    nodes.slow.delayMs = 2_500;
    let signedOut: Response;
    let seconds: number;
    try {
      const started = Date.now();
      signedOut = await call(here.cookie, '/api/auth/sign-out', 'POST');
      seconds = (Date.now() - started) / 1000;
      expect(signedOut.status).toBe(200);
      expect(seconds).toBeLessThan(4.5);
      expect(await signedOut.json()).toMatchObject({ success: true, renewalLeases: { stopped: 0, notStopped: 1 } });
      expect(await prisma.session.count({ where: { id: here.id } })).toBe(0);
      // The replay and the revocation (2.5 s each) complete after the answer, and settle the lease.
      for (let attempt = 0; attempt < 40 && !await stopped(leaseCid); attempt++) await delay(250);
      expect(await stopped(leaseCid)).toBe(true);
    } finally {
      nodes.slow.delayMs = 0;
    }
  }, 30_000);

  test('a bare 403 from something in front of the node never settles a lease as never admitted', async () => {
    const owner = await account();
    const { cookie } = await owner.session();
    const leaseCid = await lease(owner, null, 'cdn', 3_600_000, true);
    nodes.cdn.calls.length = 0;
    expect((await call(cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', {})).status).toBe(503);
    expect(nodes.cdn.calls).toEqual(['/delegate', '/revoke']);
    const row = await prisma.renewalLease.findUniqueOrThrow({ where: { leaseCid } });
    expect([row.revokedAt, row.neverAdmittedAt, row.leaseAuthorization !== null]).toEqual([null, null, true]);
  });

  test('a confirmed lease is never settled as never admitted, whatever the node says', async () => {
    const owner = await account();
    const { cookie } = await owner.session();
    const leaseCid = await lease(owner, null, 'gone');
    expect((await call(cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', {})).status).toBe(503);
    const row = await prisma.renewalLease.findUniqueOrThrow({ where: { leaseCid } });
    expect([row.admittedAt !== null, row.neverAdmittedAt, row.revokedAt]).toEqual([true, null, null]);
  });

  test('a lease reserved after deletion\'s revoke pass is caught under the user lock: nothing deleted, step-up kept, the retry settles it', async () => {
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const owner = await account();
    const here = await owner.session();
    await writeStepUpMarker(prisma, 'delete_account', here.id, 'email');
    let late: string | undefined;
    afterRevokePass = async () => { late = await lease(owner, null, 'ok', 3_600_000, true); };
    let refused: Response;
    try {
      refused = await call(here.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' });
    } finally {
      afterRevokePass = undefined;
    }
    expect(late).toBeDefined();
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ code: 'renewal_leases_not_stopped' });
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
    // The step-up was not spent: the same marker deletes on retry, after settling the late lease.
    nodes.ok.calls.length = 0;
    expect((await call(here.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' })).status).toBe(200);
    expect(nodes.ok.calls).toEqual(['/delegate', '/revoke']);
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
  });

  /**
   * A real leased approval (managed key) whose node admission is held open while account deletion runs: the lease is
   * reserved before the node is asked, and the approval request never holds the signed lease. After Bobbie's
   * TC-2946 review schedule.
   */
  async function deletionDuringAdmission(nodeName: 'ok' | 'down') {
    const { generateKeyPairSync } = await import('node:crypto');
    const { prepareSession, completeSessionSetup } = await import('@tinycloud/node-sdk-wasm');
    const { strictSessionDid } = await import('../services/device-authorization');
    const route = await import('../routes/approval-requests');
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const node = nodes[nodeName];
    const owner = await account();
    const here = await owner.session();
    await writeStepUpMarker(prisma, 'delete_account', here.id, 'email');
    const target = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string };
    const resultKey = await crypto.subtle.exportKey('jwk', (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])).publicKey);
    const space = `tinycloud:pkh:eip155:1:${owner.wallet.address}:default`;
    const nodeIdentity = { nodeDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', renewerDid: 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp', renewerPublicKey: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik', renewerEpoch: 0 };
    const prepared = prepareSession({
      abilities: {}, rawAbilities: { [`${space}/kv/proof`]: ['tinycloud.kv/get'] }, address: owner.wallet.address, chainId: 1,
      domain: 'cli.tinycloud.xyz', spaceId: space, jwk: target, delegateUri: strictSessionDid(target),
      nonce: 'race1234567890', issuedAt: new Date(Date.now() - 1000).toISOString(), expirationTime: new Date(Date.now() + 600000).toISOString(),
    });
    const signature = await owner.wallet.signMessage({ message: prepared.siwe });
    const original = completeSessionSetup({ ...prepared, signature });
    const delegation = { ...original, signature, ownerDid: `did:pkh:eip155:1:${owner.wallet.address}`, verificationMethod: strictSessionDid(target), jwk: target, siwe: prepared.siwe, spaceId: space, hostActivated: true };
    const request = { issuer: strictSessionDid(target), targetDid: strictSessionDid(target), targetPublicJwk: target, nodeOrigin: node.origin,
      permissions: [{ service: 'tinycloud.kv', space, path: 'proof', actions: ['tinycloud.kv/get'] }],
      grantLifetimeSeconds: 600, renewal: { version: 1, leaseLifetimeSeconds: 3600 },
      resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: resultKey.x!, y: resultKey.y! } };
    const id = randomBytes(16).toString('hex');
    await prisma.approvalRequest.create({ data: { id, bodyCid: 'body', issuer: request.issuer, request, expiresAt: new Date(Date.now() + 600000) } });
    const body = { approvalRequestId: id, jwk: target, host: node.origin, permissions: request.permissions };
    await route.admitApprovalDelegation(body);
    const oldFetch = globalThis.fetch;
    const oldFlag = process.env.OPENKEY_RENEWAL_LEASES;
    process.env.OPENKEY_RENEWAL_LEASES = 'enabled';
    const { promise: gate, resolve: release } = Promise.withResolvers<void>();
    const { promise: admittedPromise, resolve: admitted } = Promise.withResolvers<void>();
    let signedLease = '';
    const order: string[] = [];
    // Only the approval's own calls go through this stand-in; settling uses the fetch captured when its module loaded.
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input instanceof Request ? input.url : input));
      if (url.origin !== node.origin) throw new Error('unexpected test transport');
      if (url.pathname === '/info') return Response.json({ nodeId: nodeIdentity.nodeDid });
      if (url.pathname === '/.well-known/tinycloud/node-keys') return Response.json(nodeIdentity);
      if (url.pathname === '/delegate') {
        signedLease = new Headers(init?.headers).get('authorization') ?? '';
        order.push('approval /delegate (answer held)');
        admitted();
        await gate;
        return Response.json({});
      }
      throw new Error('unexpected test path');
    }) as typeof fetch;
    node.calls.length = 0;
    node.onCall = async (path) => { order.push(`settle ${path}`); };
    let pending: Promise<unknown> | undefined;
    let reservedDuringAdmission = false;
    let savedStep = '';
    let deletion: Response | undefined;
    let approvalOutcome: unknown;
    try {
      pending = route.saveApprovalDelegation(body, owner.userId, delegation, {
        renewal: { choice: 'leased', leaseLifetimeSeconds: 3600 }, host: node.origin, sessionId: here.id,
        signOwner: (message) => owner.wallet.signMessage({ message }),
      }).then(() => 'approved', (error) => ({ error: error.code ?? error.message }));
      expect(await Promise.race([admittedPromise.then(() => 'admitted'), pending])).toBe('admitted');
      reservedDuringAdmission = (await prisma.renewalLease.count({ where: { userId: owner.userId, admittedAt: null } })) === 1;
      savedStep = JSON.stringify((await prisma.approvalRequest.findUniqueOrThrow({ where: { id } })).renewal);
      deletion = await call(here.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' });
    } finally {
      release();
      if (pending) approvalOutcome = await pending;
      globalThis.fetch = oldFetch;
      node.onCall = undefined;
      if (oldFlag === undefined) delete process.env.OPENKEY_RENEWAL_LEASES;
      else process.env.OPENKEY_RENEWAL_LEASES = oldFlag;
    }
    return {
      reservedDuringAdmission, deletion: deletion!, order, approvalOutcome,
      signedLease: signedLease.replace(/^Bearer\s+/i, ''), savedStep,
      savedStepAfter: JSON.stringify((await prisma.approvalRequest.findUnique({ where: { id } }))?.renewal ?? null),
      users: await prisma.user.count({ where: { id: owner.userId } }),
      keys: await prisma.ethereumKey.count({ where: { userId: owner.userId } }),
    };
  }

  test('deletion during a held admission: the lease was reserved first, so deletion settles it at the node before any key goes', async () => {
    const result = await deletionDuringAdmission('ok');
    expect(result.reservedDuringAdmission).toBe(true);
    expect(result.deletion.status).toBe(200);
    expect(result.order).toEqual(['approval /delegate (answer held)', 'settle /delegate', 'settle /revoke']);
    expect([result.users, result.keys]).toEqual([0, 0]);
    expect(result.approvalOutcome).not.toBe('approved');
  }, 30_000);

  test('deletion during a held admission is refused when the node can\'t settle it; nothing is deleted', async () => {
    const result = await deletionDuringAdmission('down');
    expect(result.reservedDuringAdmission).toBe(true);
    expect(result.deletion.status).toBe(409);
    expect(await result.deletion.json()).toMatchObject({ code: 'renewal_leases_not_stopped', nodeUnavailable: 1 });
    expect([result.users, result.keys]).toEqual([1, 1]);
  }, 30_000);

  test('the approval request never holds the signed lease: only its reservation does, encrypted', async () => {
    const result = await deletionDuringAdmission('ok');
    expect(result.signedLease.length).toBeGreaterThan(20);
    expect(result.savedStep).toContain('leaseCid');
    expect(result.savedStep).not.toContain('leaseAuthorization');
    expect(result.savedStep).not.toContain(result.signedLease);
    expect(result.savedStepAfter).not.toContain(result.signedLease);
  }, 30_000);

  test.skipIf(backend !== 'postgres')('sign-out never waits behind another request holding the account (a slow deletion): the session ends, the leases stay on', async () => {
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const owner = await account();
    const here = await owner.session();
    const other = await owner.session();
    await writeStepUpMarker(prisma, 'delete_account', other.id, 'email');
    // Three unconfirmed leases on a node that answers only after 6 s: deletion's settle holds the user lock for a long time.
    const leases = [await lease(owner, here.id, 'slow', 3_600_000, true), await lease(owner, null, 'slow', 3_600_000, true), await lease(owner, null, 'slow', 3_600_000, true)];
    nodes.slow.delayMs = 6_000;
    let signOut: Response;
    let seconds: number;
    let deleting: Promise<Response> | undefined;
    try {
      deleting = Promise.resolve(call(other.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' }));
      await delay(500);
      const started = Date.now();
      signOut = await call(here.cookie, '/api/auth/sign-out', 'POST');
      seconds = (Date.now() - started) / 1000;
    } finally {
      await deleting;
      nodes.slow.delayMs = 0;
    }
    expect(signOut.status).toBe(200);
    // Well inside the sign-out's 3 s answer budget: it gives up on the busy lock at once instead of waiting.
    expect(seconds).toBeLessThan(2);
    expect(await signOut.json()).toMatchObject({ success: true, renewalLeases: { stopped: 0 } });
    expect(await prisma.session.count({ where: { id: here.id } })).toBe(0);
    // The node never answered in time, so none of them was settled: all still on, for the next attempt.
    expect(await prisma.renewalLease.count({ where: { leaseCid: { in: leases }, revokedAt: null, neverAdmittedAt: null } })).toBe(3);
  }, 120_000);

  test.skipIf(backend !== 'postgres')('an approval confirming a lease while it is being settled is never overwritten as never admitted', async () => {
    const { createPrismaApprovalRequestStore } = await import('../services/approval-request-store');
    const owner = await account();
    const { cookie } = await owner.session();
    const leaseCid = await lease(owner, null, 'gone', 3_600_000, true);
    const reserved = await prisma.renewalLease.findUniqueOrThrow({ where: { leaseCid } });
    const store = createPrismaApprovalRequestStore(prisma);
    let confirmed: boolean | undefined;
    nodes.gone.onCall = async (path) => {
      if (path !== '/delegate' || confirmed !== undefined) return;
      // The approval's own admission succeeded; its save commits while the settle is between its read and its write.
      const now = new Date();
      const marker = await store.admit(reserved.approvalRequestId, now);
      confirmed = await store.approve(reserved.approvalRequestId, {
        resultRef: randomBytes(8).toString('hex'), approvedByUserId: owner.userId, ownerDid: reserved.ownerDid, encryptedResult: '{}',
        delegationExpiresAt: new Date(now.getTime() + 3_600_000), resultExpiresAt: new Date(now.getTime() + 600_000),
        lease: { leaseCid, userId: owner.userId, sessionId: null, approvalRequestId: reserved.approvalRequestId, ownerDid: reserved.ownerDid, originalCid: reserved.originalCid, nodeOrigin: reserved.nodeOrigin },
      } as never, now, marker!);
    };
    try {
      await call(cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', {});
    } finally {
      nodes.gone.onCall = undefined;
    }
    const after = await prisma.renewalLease.findUniqueOrThrow({ where: { leaseCid } });
    expect(confirmed).toBe(true);
    expect([after.admittedAt !== null, after.neverAdmittedAt]).toEqual([true, null]);
  });

  test.skipIf(backend !== 'postgres')('two simultaneous stops of one unconfirmed lease settle it once, and both say it stopped', async () => {
    const owner = await account();
    const { cookie } = await owner.session();
    const leaseCid = await lease(owner, null, 'slow', 3_600_000, true);
    nodes.slow.calls.length = 0;
    nodes.slow.delayMs = 500;
    try {
      const statuses = (await Promise.all([1, 2].map(() => call(cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', {})))).map((r) => r.status);
      expect(nodes.slow.calls).toEqual(['/delegate', '/revoke']);
      expect(statuses).toEqual([200, 200]);
    } finally {
      nodes.slow.delayMs = 0;
    }
  });
}
