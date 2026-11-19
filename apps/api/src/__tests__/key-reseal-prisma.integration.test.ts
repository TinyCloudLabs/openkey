import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { deriveNostrPubkey, sealingKid, SealingKeyring, type SealingKeyProvider } from '@openkey/tee';
import { privateKeyToAccount } from 'viem/accounts';
import { runKeyReseal, type KeyResealKind, type KeyResealRepository, type KeyResealRow } from '../services/key-reseal';
import { FileKeyResealCursorStore, type KeyResealCursor, type KeyResealCursorStore } from '../services/key-reseal-cursor';
import { PrismaKeyResealRepository } from '../services/key-reseal-prisma';
import { recordSealingBinding } from '../services/key-sealing';

// Route tests replace @openkey/db process-wide. Keep these acceptance cases
// isolated without reading or copying the operator's environment.
if (Reflect.get(globalThis, Symbol.for('openkey.test.key-reseal-prisma-isolated')) !== true) {
  test('runs five real Prisma re-seal acceptance cases in isolation', async () => {
    const child = Bun.spawn([
      process.execPath, 'test', '--preload',
      new URL('./key-reseal-prisma-isolation.ts', import.meta.url).pathname,
      import.meta.path,
    ], { cwd: '/var/tmp', env: { NODE_ENV: 'test' }, stdout: 'pipe', stderr: 'pipe' });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
    ]);
    // Never attach raw child output to an assertion: it could contain a failed
    // database invocation. Only safe test-runner counts cross this boundary.
    const summary = stdout + stderr;
    expect({ exitCode, fivePassed: /\b5 pass\b/.test(summary), zeroFailed: /\b0 fail\b/.test(summary) })
      .toEqual({ exitCode: 0, fivePassed: true, zeroFailed: true });
  }, 120_000);
} else {

const FIXED_TIME = new Date('2026-01-01T00:00:00.000Z');
const ETHEREUM_IDS = ['e-a', 'e-b', 'e-m', 'e-z'];
const NOSTR_IDS = ['n-a', 'n-m', 'n-z'];
let database: PGlite;
let prisma: PrismaClient;
let repository: PrismaKeyResealRepository;

function testKeyring(writeKid = 1) {
  return new SealingKeyring({
    writeKid,
    providers: new Map<number, SealingKeyProvider>([0, 1].map((kid) => [kid, async (context: string) =>
      new Uint8Array(createHash('sha256').update(`TEST ONLY key-reseal-prisma/${kid}/${context}`).digest())])),
  });
}

function digest(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

class MemoryCursor implements KeyResealCursorStore {
  constructor(public value: KeyResealCursor | null = null) {}
  async load() { return structuredClone(this.value); }
  async save(value: KeyResealCursor) { this.value = structuredClone(value); }
}

function repositoryView(overrides: Partial<KeyResealRepository> = {}): KeyResealRepository {
  return {
    page: repository.page.bind(repository),
    get: repository.get.bind(repository),
    compareAndSwap: repository.compareAndSwap.bind(repository),
    remaining: repository.remaining.bind(repository),
    ...overrides,
  };
}

async function rowSnapshot() {
  // Only digests reach assertions: a failed equality never prints an envelope.
  return {
    ethereum: digest(await prisma.ethereumKey.findMany({ orderBy: { id: 'asc' } })),
    nostr: digest(await prisma.nostrKey.findMany({ orderBy: { id: 'asc' } })),
  };
}

async function updateMarkers() {
  return (await database.query<{ table_name: string; updates: number }>(
    'SELECT table_name, updates FROM key_reseal_prisma_update_audit ORDER BY table_name',
  )).rows;
}

async function allPages(kind: KeyResealKind) {
  const pages: string[][] = [];
  let afterId: string | null = null;
  while (true) {
    const rows = await repository.page(kind, afterId, 2);
    pages.push(rows.map((row) => row.id));
    if (rows.length === 0) return pages;
    afterId = rows[rows.length - 1]!.id;
  }
}

async function actualGenerationCounts() {
  const ethereum = await prisma.ethereumKey.findMany({
    where: { keyType: 'MANAGED', sealedBlob: { not: null } }, select: { sealedBlob: true },
  });
  const nostr = await prisma.nostrKey.findMany({ select: { sealedSecret: true } });
  const kids = [...ethereum.map((row) => sealingKid(row.sealedBlob!)), ...nostr.map((row) => sealingKid(row.sealedSecret))];
  return { old: kids.filter((kid) => kid === 0).length, current: kids.filter((kid) => kid === 1).length };
}

async function seedRow(id: string, kind: KeyResealKind, ordinal: number, kid: number, legacy = false) {
  const hex = ordinal.toString(16).padStart(64, '0');
  const secret = kind === 'ethereum' ? `0x${hex}` : hex;
  const userId = `TEST-key-reseal-prisma-${id}`;
  const sealingContext = legacy ? null : createHash('sha256').update(`TEST ONLY context/${id}`).digest('base64url');
  const account = privateKeyToAccount(`0x${hex}`);
  const identity = kind === 'ethereum' ? account.address : deriveNostrPubkey(secret);
  const row: KeyResealRow = { id, kind, userId, sealingContext, identity, blob: '' };
  row.blob = await testKeyring(kid).seal(secret, recordSealingBinding(row));
  try {
    await prisma.user.create({ data: { id: userId, email: `${id}@key-reseal-prisma.test`, createdAt: FIXED_TIME, updatedAt: FIXED_TIME } });
    if (kind === 'ethereum') {
      await prisma.ethereumKey.create({ data: {
        id, userId, address: identity, publicKey: account.publicKey, sealedBlob: row.blob,
        sealingContext, keyType: 'MANAGED', createdAt: FIXED_TIME,
        archivedAt: id === 'e-z' ? FIXED_TIME : null,
      } });
    } else {
      await prisma.nostrKey.create({ data: {
        id, userId, pubkeyHex: identity, npub: `TEST-only-npub-${id}`, sealedSecret: row.blob,
        sealingContext: sealingContext!, createdAt: FIXED_TIME, revokedAt: id === 'n-z' ? FIXED_TIME : null,
      } });
    }
  } catch {
    throw new Error('Test fixture insert failed');
  }
  return row;
}

beforeAll(async () => {
  const root = new URL('../../../../packages/db/prisma/migrations/', import.meta.url);
  const names = (await readdir(root, { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  database = new PGlite();
  await database.waitReady;
  for (const name of names) await database.exec(await readFile(new URL(`${name}/migration.sql`, root), 'utf8'));
  prisma = new PrismaClient({ adapter: new PrismaPGlite(database) });
  repository = new PrismaKeyResealRepository(prisma);
  // Statement-level markers also detect UPDATE statements that match zero rows.
  // These test-only objects do not change the tracked schema or migrations.
  await database.exec(`
    CREATE TABLE key_reseal_prisma_update_audit (table_name text PRIMARY KEY, updates integer NOT NULL DEFAULT 0);
    INSERT INTO key_reseal_prisma_update_audit (table_name) VALUES ('ethereum_keys'), ('nostr_keys');
    CREATE FUNCTION key_reseal_prisma_record_update() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      UPDATE key_reseal_prisma_update_audit SET updates = updates + 1 WHERE table_name = TG_TABLE_NAME;
      RETURN NULL;
    END;
    $$;
    CREATE TRIGGER key_reseal_prisma_ethereum_update AFTER UPDATE ON ethereum_keys
      FOR EACH STATEMENT EXECUTE FUNCTION key_reseal_prisma_record_update();
    CREATE TRIGGER key_reseal_prisma_nostr_update AFTER UPDATE ON nostr_keys
      FOR EACH STATEMENT EXECUTE FUNCTION key_reseal_prisma_record_update();
  `);
}, 120_000);

afterAll(async () => {
  try { await prisma?.$disconnect(); } finally { await database?.close(); }
});

beforeEach(async () => {
  await database.exec('TRUNCATE "user" CASCADE; UPDATE key_reseal_prisma_update_audit SET updates = 0');
  // Insertion order intentionally disagrees with the repository's keyset order.
  await seedRow('e-z', 'ethereum', 11, 0);
  await seedRow('e-a', 'ethereum', 12, 1);
  await seedRow('e-m', 'ethereum', 13, 0, true);
  await seedRow('e-b', 'ethereum', 14, 1);
  const external = await seedRow('e-external', 'ethereum', 15, 0);
  await seedRow('e-null', 'ethereum', 16, 0);
  // Independently exercise both exclusion predicates, including an external row
  // with a perfectly readable old-generation blob.
  try {
    await prisma.ethereumKey.update({ where: { id: external.id }, data: { keyType: 'EXTERNAL' } });
    await prisma.ethereumKey.update({ where: { id: 'e-null' }, data: { sealedBlob: null } });
  } catch {
    throw new Error('Test fixture exclusion setup failed');
  }
  await seedRow('n-z', 'nostr', 21, 0);
  await seedRow('n-a', 'nostr', 22, 1);
  await seedRow('n-m', 'nostr', 23, 0);
  await database.exec('UPDATE key_reseal_prisma_update_audit SET updates = 0');
});

describe('Prisma versioned sealing and re-seal maintenance', () => {
  test('traverses both tables exactly once and applies all old generations, including legacy and inactive rows', async () => {
    expect(await allPages('ethereum')).toEqual([['e-a', 'e-b'], ['e-m', 'e-z'], []]);
    expect(await allPages('nostr')).toEqual([['n-a', 'n-m'], ['n-z'], []]);
    expect(await repository.get('ethereum', 'e-external')).toBeNull();
    expect(await repository.get('ethereum', 'e-null')).toBeNull();
    expect((await prisma.ethereumKey.findUniqueOrThrow({ where: { id: 'e-m' } })).sealingContext).toBeNull();
    expect(await actualGenerationCounts()).toEqual({ old: 4, current: 3 });
    expect(await repository.remaining(0)).toBe(4);
    expect(await repository.remaining(1)).toBe(3);
    const excludedBefore = digest(await prisma.ethereumKey.findMany({ where: { id: { in: ['e-external', 'e-null'] } }, orderBy: { id: 'asc' } }));
    const visited: Record<KeyResealKind, string[]> = { ethereum: [], nostr: [] };
    const result = await runKeyReseal({
      repository: repositoryView({ page: async (kind, afterId, take) => {
        const rows = await repository.page(kind, afterId, take);
        visited[kind].push(...rows.map((row) => row.id));
        return rows;
      } }),
      keyring: testKeyring(), cursorStore: new MemoryCursor(), pageSize: 2, dryRun: false,
    });
    expect(result).toEqual({ dryRun: false, scanned: 7, alreadyCurrent: 3, resealed: 4, raced: 0, failed: 0, remainingOldGeneration: 0 });
    expect(visited).toEqual({ ethereum: ETHEREUM_IDS, nostr: NOSTR_IDS });
    expect(await actualGenerationCounts()).toEqual({ old: 0, current: 7 });
    expect(await repository.remaining(0)).toBe(0);
    expect(await repository.remaining(1)).toBe(7);
    expect(digest(await prisma.ethereumKey.findMany({ where: { id: { in: ['e-external', 'e-null'] } }, orderBy: { id: 'asc' } }))).toBe(excludedBefore);
    expect((await prisma.ethereumKey.findUniqueOrThrow({ where: { id: 'e-z' } })).archivedAt?.getTime()).toBe(FIXED_TIME.getTime());
    expect((await prisma.nostrKey.findUniqueOrThrow({ where: { id: 'n-z' } })).revokedAt?.getTime()).toBe(FIXED_TIME.getTime());
    expect((await prisma.ethereumKey.findUniqueOrThrow({ where: { id: 'e-m' } })).sealingContext).toBeNull();
    expect(await updateMarkers()).toEqual([{ table_name: 'ethereum_keys', updates: 2 }, { table_name: 'nostr_keys', updates: 2 }]);
  });

  test.each(['ethereum', 'nostr'] as const)('preserves a concurrent %s winner when the actual CAS UPDATE matches zero rows', async (kind) => {
    const id = kind === 'ethereum' ? 'e-z' : 'n-z';
    const original = (await repository.get(kind, id))!;
    const plaintext = await testKeyring().unseal(original.blob, recordSealingBinding(original));
    const message = 'TEST ONLY key-reseal-prisma signature';
    const signatureBefore = kind === 'ethereum'
      ? digest(await privateKeyToAccount(plaintext as `0x${string}`).signMessage({ message })) : null;
    const casResults: number[] = [];
    let winnerDigest: string | null = null;
    let winnerReads = 0;
    const completeWinner = () => kind === 'ethereum'
      ? prisma.ethereumKey.findUniqueOrThrow({ where: { id } })
      : prisma.nostrKey.findUniqueOrThrow({ where: { id } });
    const racing = repositoryView({
      compareAndSwap: async (previous, replacement) => {
        if (previous.kind === kind && previous.id === id && winnerDigest === null) {
          // A real Prisma write lands after the page read, before the real CAS.
          const winningBlob = await testKeyring().seal(plaintext, recordSealingBinding(original));
          try {
            if (kind === 'ethereum') await prisma.ethereumKey.update({ where: { id }, data: { sealedBlob: winningBlob, label: 'TEST concurrent winner' } });
            else await prisma.nostrKey.update({ where: { id }, data: { sealedSecret: winningBlob, label: 'TEST concurrent winner' } });
          } catch {
            throw new Error('Test concurrent rewrite failed');
          }
          winnerDigest = digest(await completeWinner());
          const changed = await repository.compareAndSwap(previous, replacement);
          casResults.push(changed);
          return changed;
        }
        return repository.compareAndSwap(previous, replacement);
      },
      get: async (rowKind, rowId) => {
        if (rowKind === kind && rowId === id) winnerReads++;
        return repository.get(rowKind, rowId);
      },
    });
    const result = await runKeyReseal({ repository: racing, keyring: testKeyring(), cursorStore: new MemoryCursor(), pageSize: 2, dryRun: false });
    expect(casResults).toEqual([0]);
    expect(winnerReads).toBe(1);
    expect(result).toEqual({ dryRun: false, scanned: 7, alreadyCurrent: 4, resealed: 3, raced: 1, failed: 0, remainingOldGeneration: 0 });
    expect(digest(await completeWinner())).toBe(winnerDigest);
    const winner = (await repository.get(kind, id))!;
    const after = await testKeyring().unseal(winner.blob, recordSealingBinding(winner));
    expect(digest(after)).toBe(digest(plaintext));
    if (kind === 'ethereum') expect(digest(await privateKeyToAccount(after as `0x${string}`).signMessage({ message }))).toBe(signatureBefore);
    expect(await actualGenerationCounts()).toEqual({ old: 0, current: 7 });
  });

  test.each(['memory', 'file'] as const)('defaults to a complete read-only scan with an untouched persisted %s cursor', async (storage) => {
    const sentinel: KeyResealCursor = {
      version: 1, writeKid: 1, kind: 'nostr', afterId: 'n-m', completed: false,
      counts: { scanned: 91, alreadyCurrent: 17, resealed: 29, raced: 3, failed: 2, remainingOldGeneration: 8 },
    };
    let directory: string | undefined;
    try {
      const memory = new MemoryCursor(structuredClone(sentinel));
      let store: KeyResealCursorStore = memory;
      let cursorPath: string | undefined;
      let fileBefore: string | undefined;
      if (storage === 'file') {
        directory = await mkdtemp('/var/tmp/key-reseal-prisma-');
        cursorPath = join(directory, 'cursor.json');
        store = new FileKeyResealCursorStore(cursorPath);
        await store.save(sentinel);
        fileBefore = digest(await readFile(cursorPath, 'utf8'));
      }
      const before = await rowSnapshot();
      const markersBefore = await updateMarkers();
      const oldBefore = (await actualGenerationCounts()).old;
      expect(oldBefore).toBe(4);
      let loads = 0;
      let saves = 0;
      let casCalls = 0;
      let sealCalls = 0;
      const visited: Record<KeyResealKind, string[]> = { ethereum: [], nostr: [] };
      const keyring = testKeyring();
      keyring.seal = async () => { sealCalls++; throw new Error('Dry run attempted sealing'); };
      const result = await runKeyReseal({
        repository: repositoryView({
          page: async (kind, afterId, take) => {
            const rows = await repository.page(kind, afterId, take);
            visited[kind].push(...rows.map((row) => row.id));
            return rows;
          },
          compareAndSwap: async () => { casCalls++; throw new Error('Dry run attempted CAS'); },
        }),
        keyring, pageSize: 2,
        cursorStore: {
          load: async () => { loads++; return store.load(); },
          save: async (cursor) => { saves++; await store.save(cursor); },
        },
        // Omitted dryRun is deliberately the public default, not an opt-in.
      });
      expect(result).toEqual({ dryRun: true, scanned: 7, alreadyCurrent: 3, resealed: 0, raced: 0, failed: 0, remainingOldGeneration: oldBefore });
      expect(visited).toEqual({ ethereum: ETHEREUM_IDS, nostr: NOSTR_IDS });
      expect({ loads, saves, casCalls, sealCalls }).toEqual({ loads: 0, saves: 0, casCalls: 0, sealCalls: 0 });
      expect(await rowSnapshot()).toEqual(before);
      expect(await updateMarkers()).toEqual(markersBefore);
      expect(markersBefore).toEqual([{ table_name: 'ethereum_keys', updates: 0 }, { table_name: 'nostr_keys', updates: 0 }]);
      expect(await actualGenerationCounts()).toEqual({ old: 4, current: 3 });
      expect(memory.value).toEqual(sentinel);
      if (cursorPath) {
        expect(digest(await readFile(cursorPath, 'utf8'))).toBe(fileBefore);
        expect(await store.load()).toEqual(sentinel);
      }
    } finally {
      if (directory) await rm(directory, { recursive: true, force: true });
    }
  });
});
}
