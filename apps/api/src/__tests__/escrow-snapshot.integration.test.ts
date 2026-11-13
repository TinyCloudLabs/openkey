import { createEscrowTestDatabase } from './escrow-test-pg';
import { expect, test } from 'bun:test';
import { PrismaClient } from '@openkey/db';
import { PrismaPg } from '@prisma/adapter-pg';
import { createPrismaEscrowDatabase } from '../services/escrow-prisma';
import { Client } from 'pg';
import { withFencedOpenKeySnapshot, type EscrowSqlDatabase, type EscrowSqlTransaction } from '../services/escrow-snapshot';

// Explicit disposable local server only. No DATABASE_URL or production configuration.
const run = process.env.OPENKEY_ESCROW_TEST_PG === '1' ? test : test.skip;
run('real PostgreSQL fence blocks new sealed rows through validation and releases after failure', async () => {
  const fixture = await createEscrowTestDatabase();
  const local = fixture.local;
  const owner = new Client(local); const writer = new Client(local);
  await owner.connect(); await writer.connect();
  try {
    await owner.query('CREATE TABLE ethereum_keys (id text, "userId" text, "sealingContext" text, "keyType" text, "sealedBlob" text, address text, "publicKey" text NOT NULL DEFAULT \'\', "isCanonicalTinyCloud" boolean NOT NULL DEFAULT false, "keyIndex" integer NOT NULL DEFAULT 0, label text, "archivedAt" timestamptz, "createdAt" timestamptz NOT NULL DEFAULT now())');
    await owner.query('CREATE TABLE nostr_keys (id text, "userId" text, "sealingContext" text, "sealedSecret" text, "pubkeyHex" text, npub text NOT NULL DEFAULT \'\', label text, "revokedAt" timestamptz, "createdAt" timestamptz NOT NULL DEFAULT now())');
    await owner.query('CREATE TABLE user_encryption_key (id text, "userId" text, "sealedPrivateKey" text, "publicKey" text, "createdAt" timestamptz NOT NULL DEFAULT now())');
    const tx: EscrowSqlTransaction = {
      $executeRawUnsafe: async query => (await owner.query(query)).rowCount ?? 0,
      $queryRawUnsafe: async <T>(query: string) => (await owner.query(query)).rows as T,
    };
    const database: EscrowSqlDatabase = {
      $transaction: async (operation, options) => {
        expect(options.isolationLevel).toBe('RepeatableRead');
        await owner.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
        try { const result = await operation(tx); await owner.query('COMMIT'); return result; }
        catch (error) { await owner.query('ROLLBACK'); throw error; }
      },
    };
    await writer.query("SET statement_timeout = '150ms'");
    await withFencedOpenKeySnapshot(database, async snapshot => {
      expect(snapshot.inventory.paths[0]!.purpose).toBe('legacy-user-encryption-empty');
      expect(snapshot.inventory.records).toEqual([]);
      expect(snapshot.ciphertextSnapshotHash).toMatch(/^[a-f0-9]{64}$/);
      await expect(writer.query("INSERT INTO ethereum_keys(id) VALUES ('blocked')")).rejects.toMatchObject({ code: '57014' });
      expect(snapshot.rows.ethereum).toEqual([]);
    });
    await expect(withFencedOpenKeySnapshot(database, async () => { throw new Error('Validation failed'); })).rejects.toThrow('Validation failed');
    await writer.query("INSERT INTO ethereum_keys(id) VALUES ('released')");
    expect((await writer.query('SELECT id FROM ethereum_keys')).rows).toEqual([{ id: 'released' }]);
    await writer.query('DELETE FROM ethereum_keys');
    const queries: string[] = [];
    const prisma = new PrismaClient({ adapter: new PrismaPg({ ...local }), log: [{ emit: 'event', level: 'query' }] });
    prisma.$on('query', event => queries.push(event.query));
    try {
      // Commit immediately before Prisma begins the fenced operation.
      await writer.query('INSERT INTO ethereum_keys (id,"userId","sealingContext","keyType","sealedBlob",address) VALUES ($1,$2,$3,$4,$5,$6)', ['prior', 'u', null, 'MANAGED', Buffer.alloc(32, 1).toString('base64'), '0x' + 'a'.repeat(40)]);
      await withFencedOpenKeySnapshot(createPrismaEscrowDatabase(prisma), async snapshot => {
        expect(snapshot.inventory.records.map(row => row.id)).toEqual(['prior']);
        const lockIndex = queries.findIndex(query => query.startsWith('LOCK TABLE'));
        expect(lockIndex).toBeGreaterThanOrEqual(0);
        expect(queries.slice(0, lockIndex).every(query => /^(BEGIN|SET TRANSACTION)/i.test(query))).toBe(true);
      });
    } finally { await prisma.$disconnect(); }
  } finally {
    await Promise.all([owner.end(), writer.end()]);
    await fixture.cleanup();
  }
});
