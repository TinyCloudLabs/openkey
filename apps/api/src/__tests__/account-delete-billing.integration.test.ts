// TC-3903: account deletion tells billing before any row goes, and keeps a no-identifier audit row after the
// account is gone. The billing service is a loopback stand-in answering POST /api/account-delete/<address>
// the way the contract fixes it; nothing else on the network is touched. Runs on PGlite, in a spawned
// child so DATABASE_URL can point at it before the API modules open it.
import { afterAll, beforeAll, beforeEach, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';
import { mockModules } from './mock-module';

const root = resolve(import.meta.dir, '../../../..');
const ORIGIN = 'https://openkey.test';
const BILLING_SECRET = 'billing-test-secret';

if (process.env.OPENKEY_DELETE_BILLING_CI_CHILD !== '1') {
  test('account deletion settles billing first and keeps a no-identifier audit row', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_DELETE_BILLING_CI_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'account-delete-billing-ci-isolated-test-secret',
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: ORIGIN,
        CORS_ORIGIN: ORIGIN,
        RESEND_API_KEY: '',
        GOOGLE_CLIENT_ID: '',
        GOOGLE_CLIENT_SECRET: '',
        ACCOUNT_DELETE_SERVICE_SECRET: BILLING_SECRET,
      },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(exitCode, stdout + stderr).toBe(0);
  }, 300_000);
} else {
  let directory: string | undefined;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookieName: string;
  let secret: string;

  // The billing stand-in. `calls` records the address paths it was asked, in order; `authorization`
  // records the bearer it saw. `mode`: `ok` answers the contract's 200, `fail` a 5xx `{ok:false}`, and
  // `stall` never answers so the client's own ten-second timeout fires.
  const billing = {
    server: createServer(), origin: '', mode: 'ok' as 'ok' | 'fail' | 'stall', canceled: 1,
    calls: [] as string[], authorization: null as string | null,
  };
  billing.server.on('request', (request, response) => {
    if (request.method !== 'POST' || !request.url?.startsWith('/api/account-delete/')) {
      response.writeHead(404); response.end(); return;
    }
    billing.calls.push(request.url);
    billing.authorization = request.headers.authorization ?? null;
    if (billing.mode === 'stall') return; // never answered: the client aborts at its timeout
    if (billing.mode === 'fail') {
      response.writeHead(500, { 'content-type': 'application/json' });
      response.end('{"ok":false,"error":"stripe"}');
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(`{"ok":true,"deleted":{"subscriptions":${billing.canceled}},"stripe":{"canceled":${billing.canceled},"deleted":0}}`);
  });

  // One test enrols a key the moment billing has been settled, in the gap before the delete transaction:
  // the transaction's re-read under the user lock must catch it and abort retryably.
  let enrollOnBillingSettled: { userId: string; address: string } | undefined;
  await mockModules({
    '../services/billing-account-delete': (actual) => ({
      cancelBillingForAccountDelete: async (
        addresses: readonly string[],
        deps?: Parameters<typeof actual.cancelBillingForAccountDelete>[1],
      ) => {
        const settled = await actual.cancelBillingForAccountDelete(addresses, deps);
        const enroll = enrollOnBillingSettled;
        enrollOnBillingSettled = undefined;
        if (enroll) {
          await prisma.ethereumKey.create({ data: {
            userId: enroll.userId, address: enroll.address, publicKey: enroll.address,
            keyIndex: 1, keyType: 'EXTERNAL', sealedBlob: null, sealingContext: null,
          } });
        }
        return settled;
      },
    }),
  });

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-delete-billing-'));
    const database = new PGlite(directory);
    try {
      const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    } finally { await database.close(); }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;

    billing.server.listen(0, '127.0.0.1');
    await once(billing.server, 'listening');
    const bound = billing.server.address();
    billing.origin = `http://127.0.0.1:${typeof bound === 'object' && bound ? bound.port : 0}`;
    process.env.BILLING_API_URL = billing.origin;

    // Loaded after DATABASE_URL and BILLING_API_URL are set: the API modules open their database when
    // loaded, and log.ts rewrites global fetch/console — both belong only to this child process, so every
    // API import in this file is deferred inside the child branch and inside tests, never a top-level
    // static import that the parent test run would also execute.
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    const context = await authModule.auth.$context;
    cookieName = context.authCookies.sessionToken.name;
    secret = context.secret;
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    billing.server.closeAllConnections?.();
    billing.server.close();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  const call = (cookie: string, path: string, body?: unknown) => app.fetch(new Request(`https://api.openkey.test${path}`, {
    method: 'POST',
    headers: { cookie, origin: ORIGIN, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));

  async function account(addresses: string[] = []) {
    const userId = `billing-${randomUUID()}`;
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: userId, emailVerified: true } });
    for (const address of addresses) {
      await prisma.ethereumKey.create({ data: {
        userId, address, publicKey: address, keyIndex: 0, keyType: 'EXTERNAL', sealedBlob: null, sealingContext: null,
      } });
    }
    const token = randomUUID();
    const id = randomUUID();
    await prisma.session.create({ data: { id, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    await writeStepUpMarker(prisma, 'delete_account', id, 'email');
    return { userId, cookie, delete: () => call(cookie, '/api/account/delete', { confirmation: 'DELETE MY ACCOUNT' }) };
  }

  // The audit table is append-only; tests assert on its whole contents, so each starts empty. The stub
  // also resets between tests.
  beforeEach(async () => {
    await prisma.accountDeletionAudit.deleteMany();
    billing.mode = 'ok';
    billing.canceled = 1;
  });
  const auditRows = () => prisma.accountDeletionAudit.findMany({ select: { hadSubscription: true, billingOk: true } });

  test('billing is asked once per address before the delete; one audit row reports them settled', async () => {
    const addresses = [
      `0x${randomBytes(20).toString('hex')}`,
      `0x${randomBytes(20).toString('hex').replace(/./g, (c) => (/[a-f]/.test(c) ? c.toUpperCase() : c))}`,
    ];
    const owner = await account(addresses);
    billing.calls.length = 0;

    const deleted = await owner.delete();
    expect(deleted.status).toBe(200);
    // One call per address, lowercased, bearing the service secret.
    expect(billing.calls.sort()).toEqual(addresses.map((a) => `/api/account-delete/${a.toLowerCase()}`).sort());
    expect(billing.authorization).toBe(`Bearer ${BILLING_SECRET}`);
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
    expect(await prisma.ethereumKey.count({ where: { userId: owner.userId } })).toBe(0);

    expect(await auditRows()).toEqual([{ hadSubscription: true, billingOk: true }]);

    // Repeating the request is sane: the session went with the account, so it is just unauthenticated.
    const again = await owner.delete();
    expect(again.status).toBe(401);
  });

  test('a billing 5xx refuses the deletion with 503 and deletes nothing; the retry settles it', async () => {
    const address = `0x${randomBytes(20).toString('hex')}`;
    const owner = await account([address]);
    billing.calls.length = 0;
    billing.mode = 'fail';
    try {
      const refused = await owner.delete();
      expect(refused.status).toBe(503);
      expect(await refused.json()).toEqual({ error: 'billing_unavailable', code: 'billing_unavailable' });
    } finally {
      billing.mode = 'ok';
    }
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
    expect(await prisma.ethereumKey.count({ where: { userId: owner.userId } })).toBe(1);
    expect(await auditRows()).toEqual([]);

    // The same account retries once billing answers; the step-up marker was never spent by the refusal.
    const deleted = await owner.delete();
    expect(deleted.status).toBe(200);
    expect(billing.calls).toEqual([`/api/account-delete/${address}`, `/api/account-delete/${address}`]);
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
    expect(await auditRows()).toEqual([{ hadSubscription: true, billingOk: true }]);
  });

  test('a billing call that never answers refuses the deletion with 503 and deletes nothing', async () => {
    const address = `0x${randomBytes(20).toString('hex')}`;
    const owner = await account([address]);
    billing.mode = 'stall';
    try {
      const refused = await owner.delete();
      expect(refused.status).toBe(503);
      expect(await refused.json()).toEqual({ error: 'billing_unavailable', code: 'billing_unavailable' });
    } finally {
      billing.mode = 'ok';
    }
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
    expect(await prisma.ethereumKey.count({ where: { userId: owner.userId } })).toBe(1);
    expect(await auditRows()).toEqual([]);
  }, 30_000); // the client's own ~10s timeout is what this test exercises

  test('an account with no ethereum keys asks billing nothing and still deletes', async () => {
    const owner = await account([]);
    billing.calls.length = 0;
    const deleted = await owner.delete();
    expect(deleted.status).toBe(200);
    expect(billing.calls).toEqual([]);
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
    // One row: there was nothing to cancel and billing is settled (vacuously) for zero addresses.
    expect(await auditRows()).toEqual([{ hadSubscription: false, billingOk: true }]);
  });

  test('with billing unconfigured the deletion skips the calls and still deletes (non-production)', async () => {
    const saved = { BILLING_API_URL: process.env.BILLING_API_URL, ACCOUNT_DELETE_SERVICE_SECRET: process.env.ACCOUNT_DELETE_SERVICE_SECRET };
    const address = `0x${randomBytes(20).toString('hex')}`;
    const owner = await account([address]);
    billing.calls.length = 0;
    delete process.env.BILLING_API_URL;
    delete process.env.ACCOUNT_DELETE_SERVICE_SECRET;
    try {
      const deleted = await owner.delete();
      expect(deleted.status).toBe(200);
      expect(billing.calls).toEqual([]);
      expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
      expect(await auditRows()).toEqual([{ hadSubscription: false, billingOk: false }]);
    } finally {
      process.env.BILLING_API_URL = saved.BILLING_API_URL;
      process.env.ACCOUNT_DELETE_SERVICE_SECRET = saved.ACCOUNT_DELETE_SERVICE_SECRET;
    }
  });

  test('in production a non-https billing URL refuses the deletion like missing config: 503, nothing deleted, no call sent', async () => {
    const saved = process.env.TEE_MODE;
    const address = `0x${randomBytes(20).toString('hex')}`;
    const owner = await account([address]);
    billing.calls.length = 0;
    billing.authorization = null;
    // The loopback stand-in is plain http, which production must not use for the bearer secret.
    expect(billing.origin.startsWith('http://')).toBe(true);
    process.env.TEE_MODE = 'production';
    try {
      const refused = await owner.delete();
      expect(refused.status).toBe(503);
      expect(await refused.json()).toEqual({ error: 'billing_unavailable', code: 'billing_unavailable' });
    } finally {
      if (saved === undefined) delete process.env.TEE_MODE;
      else process.env.TEE_MODE = saved;
    }
    expect(billing.calls).toEqual([]);
    expect(billing.authorization).toBeNull();
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
    expect(await prisma.ethereumKey.count({ where: { userId: owner.userId } })).toBe(1);
    expect(await auditRows()).toEqual([]);
  });

  test('a key enrolled between the billing calls and the delete transaction aborts retryably; the retry bills it', async () => {
    const first = `0x${randomBytes(20).toString('hex')}`;
    const owner = await account([first]);
    const second = `0x${randomBytes(20).toString('hex')}`;
    billing.calls.length = 0;
    enrollOnBillingSettled = { userId: owner.userId, address: second };

    const refused = await owner.delete();
    expect(enrollOnBillingSettled).toBeUndefined(); // the enrolment really landed between billing and the tx
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ code: 'ethereum_keys_changed' });
    // The new key was never sent to billing and nothing was deleted — no audit row either.
    expect(billing.calls).toEqual([`/api/account-delete/${first}`]);
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
    expect(await prisma.ethereumKey.count({ where: { userId: owner.userId } })).toBe(2);
    expect(await auditRows()).toEqual([]);

    // The retry bills both addresses — the first again, idempotently — then deletes.
    const deleted = await owner.delete();
    expect(deleted.status).toBe(200);
    expect(billing.calls.slice(1).sort()).toEqual([`/api/account-delete/${first}`, `/api/account-delete/${second}`].sort());
    expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
    expect(await prisma.ethereumKey.count({ where: { userId: owner.userId } })).toBe(0);
    expect(await auditRows()).toEqual([{ hadSubscription: true, billingOk: true }]);
  });

  test('hadSubscription follows stripe.canceled in billing\'s answer, and 0 counts as false', async () => {
    billing.canceled = 0;
    const free = await account([`0x${randomBytes(20).toString('hex')}`]);
    expect((await free.delete()).status).toBe(200);
    expect(await auditRows()).toEqual([{ hadSubscription: false, billingOk: true }]);

    await prisma.accountDeletionAudit.deleteMany();
    billing.canceled = 2;
    const paying = await account([`0x${randomBytes(20).toString('hex')}`]);
    expect((await paying.delete()).status).toBe(200);
    expect(await auditRows()).toEqual([{ hadSubscription: true, billingOk: true }]);
  });

  test('the audit table has only id, deletedAt, hadSubscription and billingOk — no identifier can creep back', async () => {
    // $queryRaw is untyped; the assertion below proves the shape.
    const rows: Array<{ column_name: string }> = await prisma.$queryRaw`
      SELECT column_name FROM information_schema.columns WHERE table_name = 'account_deletion_audit'`;
    expect(rows.map((row) => row.column_name).sort()).toEqual(['billingOk', 'deletedAt', 'hadSubscription', 'id']);
  });

  test('the plan fails closed in production and skips only when fully unconfigured', async () => {
    const { billingAccountDeletePlan } = await import('../services/billing-account-delete');
    expect(billingAccountDeletePlan({ NODE_ENV: 'production' })).toEqual({ kind: 'unavailable' });
    expect(billingAccountDeletePlan({ TEE_MODE: 'production' })).toEqual({ kind: 'unavailable' });
    expect(billingAccountDeletePlan({ NODE_ENV: 'production', BILLING_API_URL: 'https://billing.test' })).toEqual({ kind: 'unavailable' });
    expect(billingAccountDeletePlan({ NODE_ENV: 'test' })).toEqual({ kind: 'skip' });
    expect(billingAccountDeletePlan({ TEE_MODE: 'development' })).toEqual({ kind: 'skip' });
    // Half-configured is a misconfiguration, never a skip, whatever the environment.
    expect(billingAccountDeletePlan({ NODE_ENV: 'test', BILLING_API_URL: 'https://billing.test' })).toEqual({ kind: 'unavailable' });
    expect(billingAccountDeletePlan({ NODE_ENV: 'test', ACCOUNT_DELETE_SERVICE_SECRET: 's' })).toEqual({ kind: 'unavailable' });
    expect(billingAccountDeletePlan({ BILLING_API_URL: 'https://billing.test/', ACCOUNT_DELETE_SERVICE_SECRET: 's' }))
      .toEqual({ kind: 'call', baseUrl: 'https://billing.test', secret: 's' });
    // Production calls billing only over https; any other scheme is unavailable, in either production flag.
    expect(billingAccountDeletePlan({ NODE_ENV: 'production', BILLING_API_URL: 'http://billing.test', ACCOUNT_DELETE_SERVICE_SECRET: 's' }))
      .toEqual({ kind: 'unavailable' });
    expect(billingAccountDeletePlan({ TEE_MODE: 'production', BILLING_API_URL: 'billing.test', ACCOUNT_DELETE_SERVICE_SECRET: 's' }))
      .toEqual({ kind: 'unavailable' });
    expect(billingAccountDeletePlan({ NODE_ENV: 'production', BILLING_API_URL: 'https://billing.test', ACCOUNT_DELETE_SERVICE_SECRET: 's' }))
      .toEqual({ kind: 'call', baseUrl: 'https://billing.test', secret: 's' });
    // Outside production the loopback http stand-in stays usable.
    expect(billingAccountDeletePlan({ NODE_ENV: 'test', BILLING_API_URL: 'http://127.0.0.1:1', ACCOUNT_DELETE_SERVICE_SECRET: 's' }))
      .toEqual({ kind: 'call', baseUrl: 'http://127.0.0.1:1', secret: 's' });
  });
}
