// TC-3353: the account-deletion receipt through the whole API (account deletion route, the internal export route,
// the tracked migrations on PGlite). Runs in a child process, as the other full-API tests do.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import { privateKeyToAccount } from 'viem/accounts';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
const ORIGIN = 'https://openkey.test';
const API = 'https://api.openkey.test';
const TOKEN = 'deletion-export-test-token';

if (process.env.OPENKEY_DELETION_RECEIPT_CI_CHILD !== '1') {
  test('the account-deletion receipt across the API', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_DELETION_RECEIPT_CI_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: API,
        BETTER_AUTH_SECRET: 'deletion-receipt-ci-isolated-test-secret',
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
} else {
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookieName: string;
  let secret: string;
  let ownerDigestFor: (address: string) => string;
  let createSealingContext: () => string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-deletion-receipt-'));
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
    ({ ownerDigestFor } = await import('../services/account-deletion-receipt'));
    ({ createSealingContext } = await import('../services/key-sealing'));
    const context = await authModule.auth.$context;
    cookieName = context.authCookies.sessionToken.name;
    secret = context.secret;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  // The table is append-only; TRUNCATE is the one thing its triggers do not cover.
  beforeEach(async () => {
    await prisma.$executeRawUnsafe('TRUNCATE "account_deletion_receipt"');
    process.env.INTERNAL_DELETION_EXPORT_TOKEN = TOKEN;
  });

  async function account(keyCount: number) {
    const userId = `deletion-${randomUUID()}`;
    const email = `${userId}@example.test`;
    const addresses = Array.from({ length: keyCount }, () => privateKeyToAccount(`0x${randomBytes(32).toString('hex')}`).address);
    await prisma.user.create({ data: { id: userId, email, name: userId, emailVerified: true } });
    for (const [index, address] of addresses.entries()) {
      await prisma.ethereumKey.create({ data: {
        userId,
        // Stored lowercase: the digest is built from the EIP-55 form.
        address: address.toLowerCase(), publicKey: address.toLowerCase(), keyIndex: index,
        keyType: index === 0 ? 'MANAGED' : 'EXTERNAL',
        sealingContext: index === 0 ? createSealingContext() : null, sealedBlob: index === 0 ? 'sealed' : null,
        // One key is archived: archived keys are deleted with the account too.
        archivedAt: index === 1 ? new Date() : null,
      } });
    }
    const token = randomUUID();
    const sessionId = randomUUID();
    await prisma.session.create({ data: { id: sessionId, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
    const { writeStepUpMarker } = await import('../services/email-otp-step-up');
    await writeStepUpMarker(prisma, 'delete_account', sessionId, 'email');
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    return { userId, email, addresses, cookie };
  }

  const deleteAccount = (cookie: string) => app.fetch(new Request(`${API}/api/account/delete`, {
    method: 'POST',
    headers: { cookie, origin: ORIGIN, 'content-type': 'application/json' },
    body: JSON.stringify({ confirmation: 'DELETE MY ACCOUNT' }),
  }));

  const exportReceipts = (query = '', token: string | null = TOKEN) => app.fetch(new Request(`${API}/api/internal/account-deletions${query}`, {
    headers: token === null ? {} : { authorization: `Bearer ${token}` },
  }));

  describe('recording', () => {
    test('a deletion writes exactly one receipt holding the digest of every key, archived or not', async () => {
      const owner = await account(3);
      const response = await deleteAccount(owner.cookie);
      expect(response.status).toBe(200);
      expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
      expect(await prisma.ethereumKey.count({ where: { address: { in: owner.addresses.map((a) => a.toLowerCase()) } } })).toBe(0);

      const receipts = await prisma.accountDeletionReceipt.findMany();
      expect(receipts).toHaveLength(1);
      const expected = owner.addresses.map((address) => createHash('sha256').update(`did:pkh:eip155:1:${address}`).digest('hex')).sort();
      expect(receipts[0]!.ownerDigests).toEqual(expected);
      expect(receipts[0]!.ownerDigests).toEqual(owner.addresses.map(ownerDigestFor).sort());
    });

    test('a deletion of an account without keys writes no receipt', async () => {
      const owner = await account(0);
      expect((await deleteAccount(owner.cookie)).status).toBe(200);
      expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(0);
      expect(await prisma.accountDeletionReceipt.count()).toBe(0);
    });

    test('a deletion that rolls back writes no receipt and keeps the keys; the retry then writes one', async () => {
      const owner = await account(2);
      // A failure after the receipt write and the key delete, at the last step of the transaction.
      await prisma.$executeRawUnsafe(`CREATE FUNCTION fail_receipt_test_user_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.id = '${owner.userId}' THEN RAISE EXCEPTION 'forced failure'; END IF;
  RETURN OLD;
END $$`);
      await prisma.$executeRawUnsafe('CREATE TRIGGER fail_receipt_test_user_delete BEFORE DELETE ON "user" FOR EACH ROW EXECUTE FUNCTION fail_receipt_test_user_delete()');
      try {
        const failed = await deleteAccount(owner.cookie);
        expect(failed.status).not.toBe(200);
      } finally {
        await prisma.$executeRawUnsafe('DROP TRIGGER fail_receipt_test_user_delete ON "user"');
        await prisma.$executeRawUnsafe('DROP FUNCTION fail_receipt_test_user_delete()');
      }
      expect(await prisma.accountDeletionReceipt.count()).toBe(0);
      expect(await prisma.user.count({ where: { id: owner.userId } })).toBe(1);
      expect(await prisma.ethereumKey.count({ where: { userId: owner.userId } })).toBe(2);

      expect((await deleteAccount(owner.cookie)).status).toBe(200);
      expect(await prisma.accountDeletionReceipt.count()).toBe(1);
    });
  });

  describe('append-only', () => {
    test('updates and deletes on a receipt are refused', async () => {
      const receipt = await prisma.accountDeletionReceipt.create({ data: { ownerDigests: ['a'.repeat(64)] } });
      // Wrapped in async functions: a Prisma query is a lazy thenable, not a Promise.
      await expect((async () => prisma.$executeRawUnsafe(`UPDATE "account_deletion_receipt" SET "ownerDigests" = ARRAY['b'] WHERE id = '${receipt.id}'`))()).rejects.toThrow(/append-only/);
      await expect((async () => prisma.$executeRawUnsafe(`DELETE FROM "account_deletion_receipt" WHERE id = '${receipt.id}'`))()).rejects.toThrow(/append-only/);
      await expect((async () => prisma.accountDeletionReceipt.update({ where: { id: receipt.id }, data: { ownerDigests: [] } }))()).rejects.toThrow(/append-only/);
      await expect((async () => prisma.accountDeletionReceipt.delete({ where: { id: receipt.id } }))()).rejects.toThrow(/append-only/);
      expect((await prisma.accountDeletionReceipt.findUnique({ where: { id: receipt.id } }))?.ownerDigests).toEqual(['a'.repeat(64)]);
    });
  });

  describe('export', () => {
    test('carries receipt id, deletion time and digests, and no raw identifier', async () => {
      const owner = await account(2);
      expect((await deleteAccount(owner.cookie)).status).toBe(200);

      const response = await exportReceipts();
      expect(response.status).toBe(200);
      expect(response.headers.get('cache-control')).toBe('no-store');
      const text = await response.text();
      const body = JSON.parse(text) as Record<string, unknown>[];
      expect(body).toHaveLength(1);
      expect(Object.keys(body[0]!).sort()).toEqual(['deletedAt', 'ownerDigests', 'receiptId']);
      expect(body[0]!.ownerDigests).toEqual(owner.addresses.map(ownerDigestFor).sort());
      expect(new Date(body[0]!.deletedAt as string).toISOString()).toBe(body[0]!.deletedAt as string);

      const haystack = text.toLowerCase();
      for (const needle of [owner.userId, owner.email, ...owner.addresses, ...owner.addresses.map((a) => a.toLowerCase()), ...owner.addresses.map((a) => a.slice(2).toLowerCase())]) {
        expect(haystack).not.toContain(needle.toLowerCase());
      }
    });

    test('is empty when nothing was deleted', async () => {
      const response = await exportReceipts();
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual([]);
    });

    test('answers 503 when the token is not configured, and 401 for a missing or wrong token', async () => {
      delete process.env.INTERNAL_DELETION_EXPORT_TOKEN;
      expect((await exportReceipts()).status).toBe(503);
      expect((await exportReceipts('', 'anything')).status).toBe(503);
      process.env.INTERNAL_DELETION_EXPORT_TOKEN = TOKEN;
      expect((await exportReceipts('', null)).status).toBe(401);
      expect((await exportReceipts('', 'wrong-token')).status).toBe(401);
      expect((await exportReceipts('', `${TOKEN}x`)).status).toBe(401);
      const noScheme = await app.fetch(new Request(`${API}/api/internal/account-deletions`, { headers: { authorization: TOKEN } }));
      expect(noScheme.status).toBe(401);
      // The metrics token does not open this route.
      process.env.INTERNAL_METRICS_TOKEN = 'metrics-token';
      try { expect((await exportReceipts('', 'metrics-token')).status).toBe(401); } finally { delete process.env.INTERNAL_METRICS_TOKEN; }
    });

    test('rejects a since that is not RFC 3339', async () => {
      for (const since of ['yesterday', '2026-11-19', '1763510400', '2026-13-45T00:00:00Z', '2026-11-19T00:00:00', '']) {
        const response = await exportReceipts(`?since=${encodeURIComponent(since)}`);
        expect(response.status, since).toBe(400);
      }
    });

    test('orders by deletion time then id, and returns only receipts strictly after since', async () => {
      const at = (seconds: number) => new Date(Date.UTC(2026, 10, 19, 12, 0, seconds));
      await prisma.accountDeletionReceipt.createMany({ data: [
        { id: 'c', deletedAt: at(30), ownerDigests: ['3'] },
        { id: 'b', deletedAt: at(20), ownerDigests: ['2b'] },
        { id: 'a', deletedAt: at(20), ownerDigests: ['2a'] },
        { id: 'd', deletedAt: at(10), ownerDigests: ['1'] },
      ] });
      const all = await (await exportReceipts()).json() as { receiptId: string }[];
      expect(all.map((row) => row.receiptId)).toEqual(['d', 'a', 'b', 'c']);

      const after = await (await exportReceipts(`?since=${encodeURIComponent(at(20).toISOString())}`)).json() as { receiptId: string }[];
      expect(after.map((row) => row.receiptId)).toEqual(['c']);

      const offset = await (await exportReceipts(`?since=${encodeURIComponent('2026-11-19T13:00:15+01:00')}`)).json() as { receiptId: string }[];
      expect(offset.map((row) => row.receiptId)).toEqual(['a', 'b', 'c']);
    });

    test('returns at most 1000 receipts; the caller continues from the last deletedAt', async () => {
      const base = Date.UTC(2026, 10, 19, 0, 0, 0);
      await prisma.accountDeletionReceipt.createMany({ data: Array.from({ length: 1001 }, (_, index) => ({
        id: `r${String(index).padStart(4, '0')}`, deletedAt: new Date(base + index * 1000), ownerDigests: ['x'],
      })) });
      const first = await (await exportReceipts()).json() as { receiptId: string; deletedAt: string }[];
      expect(first).toHaveLength(1000);
      expect(first[0]!.receiptId).toBe('r0000');
      expect(first[999]!.receiptId).toBe('r0999');
      const rest = await (await exportReceipts(`?since=${encodeURIComponent(first[999]!.deletedAt)}`)).json() as { receiptId: string }[];
      expect(rest.map((row) => row.receiptId)).toEqual(['r1000']);
    });
  });
}
