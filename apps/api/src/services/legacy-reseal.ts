// TC-3554: one-time re-seal of every key sealed under the pre-move Phala root to the current root.
//
// Sealed material is AES-GCM under sha256(GetKey(path)). Phala's move changed the root behind getKey, so rows
// sealed before it only open under the epoch-0 root, which the key-recovery sidecar can read. This pass opens
// each such row once with the epoch-0 key, seals it again under the current key, and checks the result.
//
// Fail closed: any row that cannot be classified, opened, checked or swapped stops the pass with a
// LegacyResealError. The caller (apps/api boot) lets that end the process, so the API never listens on a
// half-migrated database. Nothing here logs ids, addresses, paths or key material.
//
//  1. Each row's path comes from resolveSealingContext (the same rule every signer uses).
//  2. A row that already opens under the CURRENT key, and whose plaintext belongs to the row (address or
//     public key), is current. Re-running is a no-op, and needs no old root at all.
//  3. Otherwise it is pending. The first pending row loads the old root (`openLegacy`: sidecar, pinned root,
//     mandatory canary) before ANY row is touched. The canary row is swapped last, so it is still old-sealed
//     whenever another row is pending.
//  4. A pending row is opened with the old key, its plaintext is checked against the row's own address or
//     public key (an anchor independent of Phala and of the sidecar), sealed under the current key, re-opened
//     and re-checked, and swapped with a compare-and-swap on the ciphertext it read.
//  5. A final pass re-reads every row and requires it to be current.
import { seal, unseal } from '@openkey/tee';
import { resolveSealingContext } from './key-sealing';

export type ResealSource = 'ethereum_key' | 'nostr_key' | 'reviewer_cleanup';

export type LegacyResealCode =
  | 'reseal_config'
  | 'reseal_canary_missing'
  | 'reseal_canary_mismatch'
  | 'reseal_canary_not_pending'
  | 'reseal_row_unreadable'
  | 'reseal_row_mismatch'
  | 'reseal_old_unseal_failed'
  | 'reseal_swap_failed'
  | 'reseal_verify_failed';

/** Fixed messages; `source` and `rowId` are database ids, never key material. */
export class LegacyResealError extends Error {
  readonly code: LegacyResealCode;
  readonly source?: ResealSource;
  readonly rowId?: string;
  constructor(code: LegacyResealCode, row?: { source: ResealSource; id: string }) {
    super(`Legacy re-seal refused: ${code}`);
    this.name = 'LegacyResealError';
    this.code = code;
    this.source = row?.source;
    this.rowId = row?.id;
  }
}

export interface ResealRow {
  source: ResealSource;
  id: string;
  userId: string | null;
  sealingContext: string | null;
  sealed: string;
  /** True when `plaintext` is the secret this row is meant to hold: its address, or its public key. */
  matches(plaintext: string): boolean;
}

export interface ResealStore {
  /** Every row that holds sealed material. */
  rows(): Promise<ResealRow[]>;
  /** Replace the row's ciphertext only if it is still `row.sealed`. Resolves false when nothing changed. */
  swap(row: ResealRow, sealed: string): Promise<boolean>;
}

export interface ResealTee {
  deriveKey(path: string): Promise<Uint8Array>;
}

export interface ResealLegacy {
  legacyKey(path: string): Promise<Uint8Array>;
}

export interface ResealOptions {
  stores: readonly ResealStore[];
  tee: ResealTee;
  /** Loads the epoch-0 keys, canary first. Called at most once, before the first row is touched. */
  openLegacy: () => Promise<ResealLegacy>;
  /** The canary's row. It is swapped last. */
  canary: { source: ResealSource; id: string };
}

export interface ResealSummary {
  total: number;
  migrated: number;
  alreadyCurrent: number;
}

function pathOf(row: ResealRow): string {
  try {
    return resolveSealingContext({ userId: row.userId, sealingContext: row.sealingContext });
  } catch {
    throw new LegacyResealError('reseal_row_unreadable', row);
  }
}

async function opens(sealed: string, key: Uint8Array): Promise<string | null> {
  try {
    return await unseal(sealed, key);
  } catch {
    return null;
  }
}

function matches(row: ResealRow, plaintext: string): boolean {
  try {
    return row.matches(plaintext);
  } catch {
    return false;
  }
}

type Classified = { row: ResealRow; store: ResealStore; current: boolean };

async function classify(stores: readonly ResealStore[], tee: ResealTee): Promise<Classified[]> {
  const out: Classified[] = [];
  for (const store of stores) {
    for (const row of await store.rows()) {
      const key = await tee.deriveKey(pathOf(row));
      try {
        const plaintext = await opens(row.sealed, key);
        if (plaintext === null) {
          out.push({ row, store, current: false });
        } else if (matches(row, plaintext)) {
          out.push({ row, store, current: true });
        } else {
          // Opens under the current key but holds someone else's secret: corrupt, not old.
          throw new LegacyResealError('reseal_row_mismatch', row);
        }
      } finally {
        key.fill(0);
      }
    }
  }
  return out;
}

export async function resealLegacyRows(options: ResealOptions): Promise<ResealSummary> {
  const { stores, tee, canary } = options;
  const rows = await classify(stores, tee);
  const pending = rows.filter((entry) => !entry.current);
  const isCanary = (entry: Classified) => entry.row.source === canary.source && entry.row.id === canary.id;

  if (pending.length > 0) {
    const canaryEntry = rows.find(isCanary);
    if (!canaryEntry) throw new LegacyResealError('reseal_canary_missing');
    if (canaryEntry.current) throw new LegacyResealError('reseal_canary_not_pending', canaryEntry.row);

    // Old root, with its canary proven, before anything is written.
    const legacy = await options.openLegacy();
    const ordered = [...pending.filter((entry) => !isCanary(entry)), canaryEntry];

    for (const { row, store } of ordered) {
      const path = pathOf(row);
      const oldKey = await legacy.legacyKey(path);
      let plaintext: string | null;
      try {
        plaintext = await opens(row.sealed, oldKey);
      } finally {
        oldKey.fill(0);
      }
      if (plaintext === null) throw new LegacyResealError('reseal_old_unseal_failed', row);
      if (!matches(row, plaintext)) throw new LegacyResealError('reseal_row_mismatch', row);

      const newKey = await tee.deriveKey(path);
      try {
        const sealed = await seal(plaintext, newKey);
        const reopened = await opens(sealed, newKey);
        if (reopened !== plaintext || !matches(row, reopened)) throw new LegacyResealError('reseal_verify_failed', row);
        if (!(await store.swap(row, sealed))) throw new LegacyResealError('reseal_swap_failed', row);
      } finally {
        newKey.fill(0);
      }
    }
  }

  // Every row, re-read, must now open under the current key and belong to itself.
  const after = await classify(stores, tee);
  const stale = after.find((entry) => !entry.current);
  if (stale) throw new LegacyResealError('reseal_verify_failed', stale.row);
  return { total: after.length, migrated: pending.length, alreadyCurrent: rows.length - pending.length };
}
