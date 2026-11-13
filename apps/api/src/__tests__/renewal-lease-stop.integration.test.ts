// TC-2946: which leases each owner action stops, and what is reported, through the whole API (routes, Better
// Auth hooks, managed-key signing) on PGlite. The node is a loopback stand-in that only answers `/revoke`; the
// real node's acceptance of these revocations is covered by renewal-lease-stop.real-node.test.ts.
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import { symmetricEncrypt } from 'better-auth/crypto';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
const ORIGIN = 'https://openkey.test';

if (process.env.OPENKEY_RENEWAL_STOP_CI_CHILD !== '1') {
  test('renewal leases: dashboard stop, sign-out scopes, deletion and wallet stops', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_RENEWAL_STOP_CI_CHILD: '1',
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
  }, 180_000);
} else {
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookieName: string;
  let secret: string;
  let secretConfig: Parameters<typeof symmetricEncrypt>[0]['key'];
  // A stand-in node per behaviour: `ok` confirms every admission and revocation, `down` fails until it is switched
  // on, `gone` refuses both (it never admitted the lease and won't). Each records the paths it was asked, in order.
  type Node = { server: Server; origin: string; up: boolean; revocations: number; calls: string[] };
  const nodes: Record<'ok' | 'down' | 'gone', Node> = {} as never;

  beforeAll(async () => {
    for (const name of ['ok', 'down', 'gone'] as const) {
      const node: Node = { server: createServer(), origin: '', up: name === 'ok', revocations: 0, calls: [] };
      node.server.on('request', (request, response) => {
        const signed = request.method === 'POST' && (request.url === '/revoke' || request.url === '/delegate') && typeof request.headers.authorization === 'string';
        if (signed) node.calls.push(request.url!);
        if (signed && request.url === '/revoke') node.revocations++;
        const status = !signed ? 404 : node.up ? 200 : name === 'gone' ? 403 : 503;
        response.writeHead(status, { 'content-type': 'application/json' });
        response.end(status === 200 ? '{}' : '{"error":"no"}');
      });
      node.server.listen(0, '127.0.0.1');
      await once(node.server, 'listening');
      node.origin = `http://127.0.0.1:${(node.server.address() as { port: number }).port}`;
      nodes[name] = node;
    }
    directory = await mkdtemp(join(tmpdir(), 'openkey-renewal-stop-'));
    const database = new PGlite(directory);
    try {
      const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) {
        await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
    } finally {
      await database.close();
    }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
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
  async function lease(owner: Awaited<ReturnType<typeof account>>, sessionId: string | null, node: 'ok' | 'down' | 'gone' = 'ok', expiresInMs = 3_600_000, reserved = false) {
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

  test('a stored signed lease that no longer decrypts stays unsettled, is never called never admitted, and blocks deletion', async () => {
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    const owner = await account();
    const here = await owner.session();
    const leaseCid = await lease(owner, here.id, 'gone', 3_600_000, true);
    // As if the at-rest secret had been rotated since it was stored.
    await prisma.renewalLease.update({ where: { leaseCid }, data: { leaseAuthorization: 'sealed-with-an-old-secret' } });
    nodes.gone.calls.length = 0;
    expect((await call(here.cookie, `/api/account/renewal-leases/${leaseCid}/stop`, 'POST', {})).status).toBe(503);
    expect(nodes.gone.calls).toEqual([]);
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
}
