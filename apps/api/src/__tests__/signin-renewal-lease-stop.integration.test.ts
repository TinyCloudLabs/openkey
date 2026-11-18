// TC-2872: a lease signed at an app sign-in is recorded when OpenKey signs it, so every existing stop ends it:
// Settings, each sign-out, account deletion, the call a Terms decline makes, an Apple revocation or account
// deletion, and the "not mine" lock. The app, not OpenKey, has the node admit a sign-in lease, so a stop sends the
// stored lease to the node again before revoking it. The node is a loopback stand-in that answers `/revoke` and
// `/delegate`. Runs on PGlite, and also on Postgres when OPENKEY_TEST_POSTGRES_URL is set.
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
const ORIGIN = 'https://openkey.test';
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const backend = process.env.OPENKEY_SIGNIN_STOP_BACKEND === 'postgres' ? 'postgres' : 'pglite';

if (process.env.OPENKEY_SIGNIN_STOP_CI_CHILD !== '1') {
  for (const engine of ['pglite', 'postgres'] as const) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(`sign-in renewal leases: every stop ends them (${engine})`, async () => {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: root,
        env: {
          ...process.env,
          OPENKEY_SIGNIN_STOP_CI_CHILD: '1',
          OPENKEY_SIGNIN_STOP_BACKEND: engine,
          NODE_ENV: 'test',
          TEE_MODE: 'development',
          BETTER_AUTH_URL: 'https://api.openkey.test',
          BETTER_AUTH_SECRET: 'signin-lease-stop-ci-isolated-test-secret',
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
  const databaseName = `signin_stop_${randomBytes(6).toString('hex')}`;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookieName: string;
  let secret: string;
  // `ok` confirms every admission and revocation. `gone` refuses both, answering a revocation with the node's own
  // "not present" refusal: the app has not registered the grant (yet), so the node holds no lease to revoke.
  type NodeName = 'ok' | 'gone';
  type Node = { server: Server; origin: string; calls: string[] };
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
    directory = await mkdtemp(join(tmpdir(), 'openkey-signin-stop-'));
    const database = new PGlite(directory);
    try {
      for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    } finally { await database.close(); }
    process.env.DATABASE_URL = `pglite:${directory}`;
  }
  delete process.env.OPENKEY_DATABASE_SCHEMA;

  beforeAll(async () => {
    for (const name of ['ok', 'gone'] as const) {
      const node: Node = { server: createServer(), origin: '', calls: [] };
      node.server.on('request', (request, response) => {
        const signed = request.method === 'POST' && (request.url === '/revoke' || request.url === '/delegate') && typeof request.headers.authorization === 'string';
        if (!signed) { response.writeHead(404); response.end(); return; }
        node.calls.push(request.url!);
        if (name === 'ok') { response.writeHead(200, { 'content-type': 'application/json' }); response.end('{}'); return; }
        response.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
        response.end(request.url === '/revoke' ? 'Cannot find parent delegation' : 'Delegation refused');
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

  async function account(user: Record<string, unknown> = {}) {
    const { createTeeClient, seal } = await import('@openkey/tee');
    const { privateKeyToAccount } = await import('viem/accounts');
    const { createSealingContext } = await import('../services/key-sealing');
    const userId = `signin-${randomUUID()}`;
    const privateKey = `0x${randomBytes(32).toString('hex')}` as const;
    const wallet = privateKeyToAccount(privateKey);
    const sealingContext = createSealingContext();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true, ...user } });
    await prisma.ethereumKey.create({ data: {
      userId, address: wallet.address, publicKey: wallet.address, keyIndex: 0, keyType: 'MANAGED', sealingContext,
      sealedBlob: await seal(privateKey, await createTeeClient().deriveKey(`openkey/key/${sealingContext}`)),
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
  /**
   * A lease as a sign-in records it: through `reserveRenewalLease`, with no approval request, before the app admits
   * it. `signedAgoMs` is how long ago the lease was prepared, `recordedAgoMs` how long ago it was recorded.
   */
  async function signInLease(owner: Awaited<ReturnType<typeof account>>, sessionId: string | null, node: NodeName = 'ok', signedAgoMs = 0, recordedAgoMs = 0) {
    const { reserveRenewalLease } = await import('../services/renewal-lease-revocation');
    const leaseCid = `bafkr4i${(leaseCount++).toString().padStart(4, '0').replace(/\d/g, (d) => 'abcdefghij'[Number(d)]!)}${'b'.repeat(48)}`;
    const approvedAt = new Date(Date.now() - signedAgoMs);
    const stage = {
      leaseCid, leaseAuthorization: `signed-lease-${leaseCid}`, delegation: { siwe: 'the signed-in grant' }, chainId: 1, ownerAddress: owner.wallet.address,
      originalCid: `bafkr4isignin${'a'.repeat(46)}`, nodeIdentity: { nodeDid: 'did:key:node', renewerDid: 'did:key:renewer' },
      approvedLeaseLifetimeSeconds: 90 * 86_400, approvedAt: approvedAt.toISOString(), leaseExpiresAt: new Date(approvedAt.getTime() + 90 * 86_400_000).toISOString(),
    };
    await reserveRenewalLease(prisma, { approvalRequestId: null, userId: owner.userId, sessionId, nodeOrigin: nodes[node].origin, stage: stage as never });
    if (recordedAgoMs) await prisma.renewalLease.update({ where: { leaseCid }, data: { createdAt: new Date(Date.now() - recordedAgoMs) } });
    return leaseCid;
  }

  const call = (cookie: string, path: string, method: 'GET' | 'POST', body?: unknown) => app.fetch(new Request(`https://api.openkey.test${path}`, {
    method, headers: { cookie, origin: ORIGIN, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
  const row = (leaseCid: string) => prisma.renewalLease.findUniqueOrThrow({ where: { leaseCid } });
  const stopped = async (leaseCid: string) => (await prisma.renewalLease.findUnique({ where: { leaseCid } }))?.revokedAt != null;

  test('a sign-in lease is recorded with its signing session and its signed lease encrypted, and listed in Settings', async () => {
    const owner = await account();
    const here = await owner.session();
    const leaseCid = await signInLease(owner, here.id);
    const recorded = await row(leaseCid);
    expect(recorded).toMatchObject({ approvalRequestId: null, sessionId: here.id, admittedAt: null, revokedAt: null, neverAdmittedAt: null, nodeOrigin: nodes.ok.origin });
    expect(recorded.leaseAuthorization).not.toBeNull();
    expect(recorded.leaseAuthorization).not.toContain('signed-lease-');

    const listed = await (await call(here.cookie, '/api/account/renewal-leases', 'GET')).json() as { leases: Array<Record<string, unknown>> };
    expect(listed.leases).toEqual([expect.objectContaining({ leaseCid, signer: 'openkey', reason: null, grantSiwe: 'the signed-in grant' })]);
  });

  test('Settings stops it: the stored lease is sent to the node again, then revoked, and the copy is dropped', async () => {
    const owner = await account();
    const { cookie } = await owner.session();
    const leaseCid = await signInLease(owner, null);
    nodes.ok.calls.length = 0;
    expect((await call(cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', {})).status).toBe(200);
    expect(nodes.ok.calls).toEqual(['/delegate', '/revoke']);
    const settled = await row(leaseCid);
    expect(settled.revokedAt).not.toBeNull();
    expect(settled.leaseAuthorization).toBeNull();
  });

  test('signing out of the session that signed in stops it; signing out another, others or everywhere stops theirs', async () => {
    const owner = await account();
    const [here, there, elsewhere] = [await owner.session(), await owner.session(), await owner.session()];
    const hereLease = await signInLease(owner, here.id);
    const thereLease = await signInLease(owner, there.id);
    const elsewhereLease = await signInLease(owner, elsewhere.id);

    expect((await call(here.cookie, '/api/auth/revoke-session', 'POST', { token: there.token })).status).toBe(200);
    expect([await stopped(hereLease), await stopped(thereLease), await stopped(elsewhereLease)]).toEqual([false, true, false]);
    expect((await call(here.cookie, '/api/auth/revoke-other-sessions', 'POST')).status).toBe(200);
    expect([await stopped(hereLease), await stopped(elsewhereLease)]).toEqual([false, true]);
    const signedOut = await call(here.cookie, '/api/auth/sign-out', 'POST');
    expect(await signedOut.json()).toMatchObject({ success: true, renewalLeases: { stopped: 1, notStopped: 0 } });
    expect(await stopped(hereLease)).toBe(true);

    const second = await account();
    const one = await second.session();
    const leases = [await signInLease(second, one.id), await signInLease(second, (await second.session()).id), await signInLease(second, null)];
    expect((await call(one.cookie, '/api/auth/revoke-sessions', 'POST')).status).toBe(200);
    expect(await Promise.all(leases.map(stopped))).toEqual([true, true, true]);
  });

  test('deleting the account stops it first, then deletes', async () => {
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const owner = await account();
    const here = await owner.session();
    await signInLease(owner, here.id);
    await writeStepUpMarker(prisma, 'delete_account', here.id, 'email');
    nodes.ok.calls.length = 0;
    expect((await call(here.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' })).status).toBe(200);
    expect(nodes.ok.calls).toEqual(['/delegate', '/revoke']);
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
  });

  test('the call a Terms decline makes stops it, without waiting for the owner\'s lock', async () => {
    const { revokeRenewalLeases } = await import('../services/renewal-lease-revocation');
    const owner = await account();
    const leaseCid = await signInLease(owner, (await owner.session()).id);
    const report = await revokeRenewalLeases(prisma, owner.userId, { kind: 'all' }, undefined, { waitForLock: false });
    expect(report).toEqual({ stopped: [leaseCid], notStopped: [] });
    expect(await stopped(leaseCid)).toBe(true);
  });

  test('a node with no such lease leaves a fresh one on, since the app may still admit it; deletion waits for it', async () => {
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const owner = await account();
    const here = await owner.session();
    const fresh = await signInLease(owner, null, 'gone');
    expect((await call(here.cookie, `/api/account/renewal-leases/${fresh}/stop`, 'POST', {})).status).toBe(503);
    expect(await row(fresh)).toMatchObject({ revokedAt: null, neverAdmittedAt: null });
    expect((await row(fresh)).leaseAuthorization).not.toBeNull();
    await writeStepUpMarker(prisma, 'delete_account', here.id, 'email');
    const refused = await call(here.cookie, '/api/account/delete', 'POST', { confirmation: 'DELETE MY ACCOUNT' });
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ code: 'renewal_leases_not_stopped', nodeUnavailable: 1 });
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
  });

  test('ten minutes after it was recorded, a lease the node never admitted is settled as never admitted', async () => {
    const owner = await account();
    const { cookie } = await owner.session();
    const stale = await signInLease(owner, null, 'gone', 10 * 60_000 + 1_000, 10 * 60_000 + 1_000);
    expect((await call(cookie, `/api/account/renewal-leases/${stale}/stop`, 'POST', {})).status).toBe(200);
    const settled = await row(stale);
    expect([settled.neverAdmittedAt !== null, settled.revokedAt, settled.leaseAuthorization]).toEqual([true, null, null]);
  });

  test('a wallet lease recorded moments ago keeps its window, though its sign-in was prepared over ten minutes ago', async () => {
    const owner = await account();
    const { cookie } = await owner.session();
    // The wallet signed just before its ten minutes ran out; the stop comes two seconds later.
    const walletSigned = await signInLease(owner, null, 'gone', 10 * 60_000 + 1_000, 2_000);
    expect((await call(cookie, `/api/account/renewal-leases/${walletSigned}/stop`, 'POST', {})).status).toBe(503);
    expect(await row(walletSigned)).toMatchObject({ revokedAt: null, neverAdmittedAt: null });
  });

  async function appleLinked() {
    const owner = await account();
    const sub = `apple-${randomUUID()}`;
    await prisma.account.create({ data: { id: randomUUID(), userId: owner.userId, providerId: 'apple', accountId: sub } });
    return { owner, sub };
  }
  const appleEvent = (sub: string, type: 'consent-revoked' | 'account-deleted' | 'email-disabled') =>
    ({ jti: randomUUID(), rawType: type, type, sub, eventTimeMs: Date.now() });

  test('Apple revoking consent or deleting the Apple Account stops it; an email change does not', async () => {
    const { processAppleNotification } = await import('../services/apple-notifications');
    for (const type of ['consent-revoked', 'account-deleted'] as const) {
      const { owner, sub } = await appleLinked();
      const leaseCid = await signInLease(owner, (await owner.session()).id);
      expect(await processAppleNotification(prisma, appleEvent(sub, type))).toBe('revoked');
      expect(await stopped(leaseCid)).toBe(true);
    }
    const { owner, sub } = await appleLinked();
    const kept = await signInLease(owner, null);
    expect(await processAppleNotification(prisma, appleEvent(sub, 'email-disabled'))).toBe('email_updated');
    expect(await stopped(kept)).toBe(false);
  });

  test('"not mine" on the mailbox review locks the account and stops it', async () => {
    const owner = await account({ socialCreatedProvider: 'apple' });
    const leaseCid = await signInLease(owner, null);
    const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
    const confirmation = randomUUID();
    const binding = randomUUID();
    await prisma.verification.create({ data: {
      id: randomUUID(), identifier: `openkey-social-email-review:${digest(confirmation)}`, value: digest(binding),
      userId: owner.userId, expiresAt: new Date(Date.now() + 60_000),
    } });
    const refused = await call(`__Host-openkey_social_email_review=${binding}`, '/api/auth/social/email-sign-in/confirm', 'POST', { confirmation, decision: 'not_mine' });
    expect(refused.status).toBe(200);
    expect((await prisma.user.findUniqueOrThrow({ where: { id: owner.userId } })).lockedAt).not.toBeNull();
    expect(await stopped(leaseCid)).toBe(true);
  });
}
