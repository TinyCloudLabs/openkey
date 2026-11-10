import { describe, expect, spyOn, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { privateKeyToAccount, privateKeyToAddress } from 'viem/accounts';
import { verifyMessage } from 'viem';
import * as tee from '@openkey/tee';
import { runKeyReseal } from '../services/key-reseal';
import { FileKeyResealCursorStore } from '../services/key-reseal-cursor';
import { runResealKeys, resealKeysMain } from '../../../../scripts/reseal-keys';
import type { KeyResealRepository, KeyResealRow, KeyResealCounts } from '../services/key-reseal';
import type { KeyResealCursor, KeyResealCursorStore } from '../services/key-reseal-cursor';

const TEST_SECRET = '0x' + '01'.padStart(64, '0');
const TEST_NOSTR_SECRET = '02'.padStart(64, '0');
const TEST_CONTEXT = Buffer.alloc(32, 19).toString('base64url');
const counts = (): KeyResealCounts => ({ scanned: 0, alreadyCurrent: 0, resealed: 0, raced: 0, failed: 0, remainingOldGeneration: 0 });
const recordSealingBinding = (row: KeyResealRow) => ({
  recordId: row.id,
  sealingContext: row.sealingContext === null ? `openkey/user/${row.userId}/keys` : `openkey/key/${row.sealingContext}`,
});

function testRing(writeKid = 1, kids = [0, 1]) {
  return new tee.SealingKeyring({
    writeKid,
    providers: new Map<number, tee.SealingKeyProvider>(kids.map((kid) => [kid, async (context: string) =>
      new Uint8Array(createHash('sha256').update(`TEST ONLY/${kid}/${context}`).digest())])),
  });
}

class MemoryCursor implements KeyResealCursorStore {
  value: KeyResealCursor | null = null;
  failAfterId: string | null = null;
  async load() { return this.value === null ? null : structuredClone(this.value); }
  async save(value: KeyResealCursor) {
    if (this.failAfterId !== null && value.afterId === this.failAfterId) throw new Error(TEST_SECRET);
    this.value = structuredClone(value);
  }
}

class MemoryRepository implements KeyResealRepository {
  rows: KeyResealRow[];
  writes = 0;
  signature = 'unchanged';
  beforeCas?: (row: KeyResealRow, repo: MemoryRepository) => void | Promise<void>;
  afterCas?: (row: KeyResealRow, repo: MemoryRepository) => void;
  constructor(rows: KeyResealRow[]) { this.rows = structuredClone(rows); }
  async page(kind: KeyResealRow['kind'], afterId: string | null, take: number) {
    return structuredClone(this.rows.filter((row) => row.kind === kind && (afterId === null || row.id > afterId))
      .sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0).slice(0, take));
  }
  async get(kind: KeyResealRow['kind'], id: string) {
    const row = this.rows.find((row) => row.kind === kind && row.id === id);
    return row ? structuredClone(row) : null;
  }
  async compareAndSwap(old: KeyResealRow, blob: string) {
    await this.beforeCas?.(old, this);
    const row = this.rows.find((row) => row.kind === old.kind && row.id === old.id);
    if (!row || row.blob !== old.blob || row.identity !== old.identity || row.userId !== old.userId || row.sealingContext !== old.sealingContext) return 0;
    row.blob = blob;
    this.writes++;
    this.afterCas?.(row, this);
    return 1;
  }
  async remaining(oldKid: number) {
    return this.rows.filter((row) => tee.sealingKid(row.blob) === oldKid).length;
  }
}

async function fixture(id: string, kind: KeyResealRow['kind'] = 'ethereum', kid = 0, legacy = false): Promise<KeyResealRow> {
  const secret = kind === 'ethereum' ? TEST_SECRET : TEST_NOSTR_SECRET;
  const row: KeyResealRow = {
    id, kind, userId: 'TEST-user', sealingContext: legacy ? null : TEST_CONTEXT,
    identity: kind === 'ethereum' ? privateKeyToAddress(secret as `0x${string}`) : tee.deriveNostrPubkey(secret),
    blob: '',
  };
  row.blob = await testRing(kid).seal(secret, recordSealingBinding(row));
  return row;
}

async function run(repository: MemoryRepository, cursorStore = new MemoryCursor(), options = {}) {
  return runKeyReseal({ repository, cursorStore, keyring: testRing(), pageSize: 1, ...options });
}

function assertSanitized(value: unknown, rows: KeyResealRow[]) {
  const text = JSON.stringify(value);
  const contexts = rows.map((row) => recordSealingBinding(row).sealingContext);
  const providerKeys = contexts.flatMap((context) => [0, 1].flatMap((kid) => {
    const bytes = createHash('sha256').update(`TEST ONLY/${kid}/${context}`).digest();
    return [bytes.toString('hex'), bytes.toString('base64')];
  }));
  const secretBase64 = [TEST_SECRET.slice(2), TEST_NOSTR_SECRET].map((hex) => Buffer.from(hex, 'hex').toString('base64'));
  for (const material of [TEST_SECRET, TEST_SECRET.slice(2), TEST_NOSTR_SECRET, ...secretBase64, ...providerKeys, ...rows.map((row) => row.blob)]) {
    expect(text).not.toContain(material);
  }
  expect(Object.keys(value as object).sort()).toEqual(Object.keys(counts()).sort());
  expect(Object.values(value as object).every((value) => typeof value === 'number')).toBe(true);
}

describe('versioned sealing and re-seal maintenance', () => {

  test('verifies and re-seals ethereum legacy user paths and nostr rows, then audits current rows', async () => {
    const rows = [await fixture('b', 'ethereum', 0, true), await fixture('a', 'ethereum'), await fixture('a', 'nostr')];
    const repo = new MemoryRepository(rows);
    const cursor = new MemoryCursor();
    expect(await run(repo, cursor)).toEqual({ ...counts(), scanned: 3, resealed: 3 });
    expect(repo.writes).toBe(3);
    expect(cursor.value?.completed).toBe(true);
    const second = await run(repo, cursor);
    expect(second).toEqual({ ...counts(), scanned: 3, alreadyCurrent: 3 });
    expect(repo.writes).toBe(3);
    assertSanitized(second, rows);
  });

  test('resumes a mid-batch crash and never re-seals a replayed current row', async () => {
    const repo = new MemoryRepository([await fixture('a'), await fixture('b'), await fixture('c'), await fixture('d', 'nostr')]);
    const cursor = new MemoryCursor();
    cursor.failAfterId = 'b';
    const failed = await run(repo, cursor, { pageSize: 3 });
    expect(failed.failed).toBe(1);
    expect(repo.writes).toBe(2);
    cursor.failAfterId = null;
    const resumed = await run(repo, cursor, { pageSize: 3 });
    expect(resumed).toEqual({ ...counts(), scanned: 4, alreadyCurrent: 1, resealed: 3 });
    expect(repo.writes).toBe(4);
  });

  test('rejects a different write generation on an incomplete cursor without writes', async () => {
    const repo = new MemoryRepository([await fixture('a')]);
    const cursor = new MemoryCursor();
    cursor.value = { version: 1, writeKid: 2, kind: 'ethereum', afterId: null, completed: false, counts: counts() };
    expect((await run(repo, cursor)).failed).toBe(1);
    expect(repo.writes).toBe(0);
  });

  test('loses CAS to a concurrent signer and update, preserving both winning values', async () => {
    const original = await fixture('a');
    const winner = await fixture('a', 'ethereum', 1);
    const repo = new MemoryRepository([original]);
    const message = 'TEST concurrent signing during re-seal maintenance';
    repo.beforeCas = async (row, repository) => {
      repository.beforeCas = undefined;
      const fresh = await repository.get(row.kind, row.id);
      if (!fresh) throw new Error('TEST missing signing row');
      const privateKey = await testRing().unseal(fresh.blob, recordSealingBinding(fresh));
      repository.signature = await privateKeyToAccount(privateKey as `0x${string}`).signMessage({ message });
      repository.rows[0]!.blob = winner.blob;
    };
    const result = await run(repo);
    expect(result).toEqual({ ...counts(), scanned: 1, alreadyCurrent: 1, raced: 1 });
    expect(repo.rows[0]!.blob).toBe(winner.blob);
    expect(await verifyMessage({ address: original.identity as `0x${string}`, message, signature: repo.signature as `0x${string}` })).toBe(true);
    expect(repo.writes).toBe(0);
  });

  test('retries a changed old-generation winner using its fresh identity and binding', async () => {
    const repo = new MemoryRepository([await fixture('a')]);
    const winner = await fixture('a', 'ethereum', 0, true);
    repo.beforeCas = (_, repository) => {
      repository.beforeCas = undefined;
      repository.rows[0] = structuredClone(winner);
    };
    expect(await run(repo)).toEqual({ ...counts(), scanned: 1, resealed: 1, raced: 1 });
    expect(repo.rows[0]!.sealingContext).toBeNull();
    expect(await testRing().unseal(repo.rows[0]!.blob, recordSealingBinding(winner))).toBe(TEST_SECRET);
  });

  test('exhausted races fail without advancing the cursor and resume safely', async () => {
    const repo = new MemoryRepository([await fixture('a'), await fixture('b')]);
    const cursor = new MemoryCursor();
    repo.beforeCas = () => { throw new Error(TEST_SECRET); };
    expect((await run(repo, cursor)).failed).toBe(1);
    expect(cursor.value?.afterId ?? null).toBeNull();
    repo.beforeCas = undefined;
    // An actual lost CAS on each attempt, not an operational exception.
    const cas = repo.compareAndSwap.bind(repo);
    repo.compareAndSwap = async () => 0;
    const failed = await run(repo, cursor, { maxRaceRetries: 1 });
    expect(failed.failed).toBe(1);
    expect(failed.raced).toBe(2);
    expect(cursor.value?.afterId ?? null).toBeNull();
    repo.compareAndSwap = cas;
    expect((await run(repo, cursor)).resealed).toBe(2);
  });

  test.each([0, 1])('identity mismatch at kid %i aborts before any later writes, including current rows', async (kid) => {
    const bad = await fixture('a', 'ethereum', kid);
    bad.identity = privateKeyToAddress(('0x' + TEST_NOSTR_SECRET) as `0x${string}`);
    const rows = [bad, await fixture('b'), await fixture('a', 'nostr')];
    const repo = new MemoryRepository(rows);
    const result = await run(repo);
    expect(result.failed).toBe(1);
    expect(result.scanned).toBe(1);
    expect(repo.writes).toBe(0);
    assertSanitized(result, rows);
  });

  test('nostr identity mismatch aborts without writes', async () => {
    const bad = await fixture('a', 'nostr');
    bad.identity = '00'.repeat(32);
    const repo = new MemoryRepository([bad, await fixture('b', 'nostr')]);
    expect((await run(repo)).failed).toBe(1);
    expect(repo.writes).toBe(0);
  });

  test('postwrite database corruption fails immediately and leaves the row resumable', async () => {
    const repo = new MemoryRepository([await fixture('a'), await fixture('b')]);
    const cursor = new MemoryCursor();
    repo.afterCas = (row) => { row.blob = 'TEST corrupt database blob'; };
    const result = await run(repo, cursor);
    expect(result.failed).toBe(1);
    expect(repo.writes).toBe(1);
    expect(result.resealed).toBe(0);
    expect(cursor.value?.afterId ?? null).toBeNull();
  });

  test('unknown provider and operational errors produce only safe counts', async () => {
    const rows = [await fixture('a', 'ethereum', 1)];
    const repo = new MemoryRepository(rows);
    const result = await run(repo, new MemoryCursor(), { keyring: testRing(2, [2]) });
    expect(result.failed).toBe(1);
    expect(repo.writes).toBe(0);
    assertSanitized(result, rows);
    repo.page = async () => { throw new Error(rows[0]!.blob + TEST_SECRET); };
    assertSanitized(await run(repo), rows);
  });

  test('full remaining pass detects an old-generation row inserted behind the cursor', async () => {
    const repo = new MemoryRepository([await fixture('b')]);
    const inserted = await fixture('a');
    repo.afterCas = (_, repository) => {
      repository.afterCas = undefined;
      repository.rows.push(inserted);
    };
    const cursor = new MemoryCursor();
    const result = await run(repo, cursor);
    expect(result.remainingOldGeneration).toBe(1);
    expect(result.failed).toBe(1);
    expect(cursor.value?.completed).not.toBe(true);
    expect((await run(repo, cursor)).failed).toBe(0);
    expect(repo.writes).toBe(2);
  });

  test('file cursor survives reconstruction with private atomic replacement and no material', async () => {
    const directory = await mkdtemp(join('/var/tmp', 'TEST-reseal-'));
    try {
      const path = join(directory, 'cursor.json');
      const store = new FileKeyResealCursorStore(path);
      expect(await store.load()).toBeNull();
      const value: KeyResealCursor = { version: 1, writeKid: 1, kind: 'ethereum', afterId: 'TEST-id', completed: false, counts: counts() };
      await store.save(value);
      expect(await new FileKeyResealCursorStore(path).load()).toEqual(value);
      await store.save({ ...value, completed: true });
      expect((await store.load())?.completed).toBe(true);
      expect(await readdir(directory)).toEqual(['cursor.json']);
      expect(await readFile(path, 'utf8')).not.toContain(TEST_SECRET);
      expect(() => new FileKeyResealCursorStore('relative.json')).toThrow();
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  test('callable entrypoint and CLI errors expose only sanitized counts', async () => {
    const directory = await mkdtemp(join('/var/tmp', 'TEST-reseal-entry-'));
    try {
      const rows = [await fixture('a')];
      const repo = new MemoryRepository(rows);
      repo.page = async () => { throw new Error(TEST_SECRET + rows[0]!.blob); };
      const result = await runResealKeys({ repository: repo, keyring: testRing(), cursorPath: join(directory, 'cursor.json') });
      expect(result.failed).toBe(1);
      assertSanitized(result, rows);
      const logs: string[] = [];
      expect(await resealKeysMain([], (text) => logs.push(text))).toBe(1);
      assertSanitized(JSON.parse(logs[0]!), rows);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  test('library output and console capture contain no fixture material on failure', async () => {
    const rows = [await fixture('a'), await fixture('b', 'nostr')];
    const repository = new MemoryRepository(rows);
    repository.page = async () => { throw new Error(rows[0]!.blob + TEST_SECRET); };
    const logs: string[] = [];
    const spies = (['log', 'error', 'warn', 'debug'] as const).map((method) =>
      spyOn(console, method).mockImplementation((...args: unknown[]) => { logs.push(JSON.stringify(args)); }));
    try {
      const result = await run(repository);
      assertSanitized(result, rows);
      expect(logs).toEqual([]);
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });
});
