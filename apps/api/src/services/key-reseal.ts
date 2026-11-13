import { deriveNostrPubkey, sealingKid, type SealingKeyring } from '@openkey/tee';
import { privateKeyToAddress } from 'viem/accounts';
import { recordSealingBinding } from './key-sealing';
import type { KeyResealCursor, KeyResealCursorStore } from './key-reseal-cursor';

export type KeyResealKind = 'ethereum' | 'nostr';

/** Internal repository data; never include a row in maintenance output. */
export interface KeyResealRow {
  kind: KeyResealKind;
  id: string;
  userId: string | null;
  sealingContext: string | null;
  identity: string;
  blob: string;
}

export interface KeyResealRepository {
  page(kind: KeyResealKind, afterId: string | null, take: number): Promise<KeyResealRow[]>;
  get(kind: KeyResealKind, id: string): Promise<KeyResealRow | null>;
  compareAndSwap(previous: KeyResealRow, blob: string): Promise<number>;
  remaining(oldKid: number): Promise<number>;
}

export interface KeyResealCounts {
  scanned: number;
  alreadyCurrent: number;
  resealed: number;
  raced: number;
  failed: number;
  remainingOldGeneration: number;
}

export interface KeyResealResult extends KeyResealCounts {
  dryRun: boolean;
}

export interface KeyResealOptions {
  repository: KeyResealRepository;
  keyring: SealingKeyring;
  cursorStore: KeyResealCursorStore;
  /** Verification-only unless a caller explicitly requests writes. */
  dryRun?: boolean;
  pageSize?: number;
  maxRaceRetries?: number;
  oldKid?: number;
}

export function emptyKeyResealCounts(): KeyResealCounts {
  return { scanned: 0, alreadyCurrent: 0, resealed: 0, raced: 0, failed: 0, remainingOldGeneration: 0 };
}

function initialCursor(writeKid: number): KeyResealCursor {
  return { version: 1, writeKid, kind: 'ethereum', afterId: null, completed: false, counts: emptyKeyResealCounts() };
}

async function verifiedPlaintext(row: KeyResealRow, keyring: SealingKeyring): Promise<string> {
  const plaintext = await keyring.unseal(row.blob, recordSealingBinding(row));
  const identity = row.kind === 'ethereum'
    ? privateKeyToAddress(plaintext as `0x${string}`)
    : deriveNostrPubkey(plaintext);
  if (identity.toLowerCase() !== row.identity.toLowerCase()) throw new Error('Key verification failed');
  return plaintext;
}

function sameRecord(a: KeyResealRow, b: KeyResealRow): boolean {
  return a.kind === b.kind && a.id === b.id && a.userId === b.userId
    && a.sealingContext === b.sealingContext && a.identity === b.identity;
}

/**
 * Versioned sealing and re-seal maintenance. Checkpoints follow verification,
 * including a new database read after each successful CAS. A failed checkpoint
 * may replay a committed row; verification then skips its current generation.
 * Run only one maintenance owner per cursor file.
 */
export async function runKeyReseal(options: KeyResealOptions): Promise<KeyResealResult> {
  const dryRun = options.dryRun !== false;
  let counts = emptyKeyResealCounts();
  try {
    const { repository, keyring, cursorStore } = options;
    const pageSize = options.pageSize ?? 100;
    const maxRaceRetries = options.maxRaceRetries ?? 3;
    const oldKid = options.oldKid ?? 0;
    if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 10_000
      || !Number.isSafeInteger(maxRaceRetries) || maxRaceRetries < 0 || maxRaceRetries > 100
      || !Number.isSafeInteger(oldKid) || oldKid < 0 || oldKid > 0xffffffff
      || (options.dryRun !== undefined && typeof options.dryRun !== 'boolean')) {
      throw new Error('Invalid maintenance configuration');
    }

    const saved = dryRun ? null : await cursorStore.load();
    if (saved && !saved.completed && saved.writeKid !== keyring.writeKid) {
      throw new Error('Maintenance target differs from checkpoint');
    }
    let cursor = saved && !saved.completed ? saved : initialCursor(keyring.writeKid);
    counts = { ...cursor.counts, failed: 0, remainingOldGeneration: 0 };
    if (!dryRun && (!saved || saved.completed)) await cursorStore.save(cursor);

    while (true) {
      const rows = await repository.page(cursor.kind, cursor.afterId, pageSize);
      if (rows.length === 0) {
        if (cursor.kind === 'ethereum') {
          cursor = { ...cursor, kind: 'nostr', afterId: null, counts: { ...counts } };
          if (!dryRun) await cursorStore.save(cursor);
          continue;
        }
        break;
      }

      for (const candidate of rows) {
        if (candidate.kind !== cursor.kind || (cursor.afterId !== null && candidate.id <= cursor.afterId)) {
          throw new Error('Invalid maintenance page');
        }
        counts.scanned++;
        let row = candidate;
        for (let attempt = 0; ; attempt++) {
          // Current-generation rows must also pass identity verification.
          const plaintext = await verifiedPlaintext(row, keyring);
          if (sealingKid(row.blob) === keyring.writeKid) {
            counts.alreadyCurrent++;
            break;
          }
          if (dryRun) break;

          const replacement = await keyring.seal(plaintext, recordSealingBinding(row));
          const changed = await repository.compareAndSwap(row, replacement);
          if (changed === 1) {
            const persisted = await repository.get(row.kind, row.id);
            if (!persisted || !sameRecord(row, persisted) || persisted.blob !== replacement) {
              throw new Error('Key verification failed');
            }
            await verifiedPlaintext(persisted, keyring);
            if (sealingKid(persisted.blob) !== keyring.writeKid) throw new Error('Key verification failed');
            counts.resealed++;
            break;
          }
          if (changed !== 0) throw new Error('Invalid maintenance update count');
          counts.raced++;
          if (attempt >= maxRaceRetries) throw new Error('Maintenance race limit reached');
          const current = await repository.get(row.kind, row.id);
          if (!current) throw new Error('Key verification failed');
          row = current;
        }

        cursor = { ...cursor, afterId: candidate.id, counts: { ...counts } };
        if (!dryRun) await cursorStore.save(cursor);
      }
    }

    // This is an independent full keyset scan, not a count of this run's writes.
    counts.remainingOldGeneration = await repository.remaining(oldKid);
    if (!dryRun && counts.remainingOldGeneration !== 0 && oldKid !== keyring.writeKid) {
      // New old-generation rows can arrive behind a checkpoint. Restart the
      // next verified pass instead of leaving them behind an exhausted cursor.
      await cursorStore.save(initialCursor(keyring.writeKid));
      throw new Error('Maintenance pass has remaining rows');
    }
    if (!dryRun) await cursorStore.save({ ...cursor, completed: true, counts: { ...counts } });
    return { ...counts, dryRun };
  } catch {
    // No exception text, row identifiers, key material, or envelopes escape.
    return { ...counts, failed: counts.failed + 1, dryRun };
  }
}
