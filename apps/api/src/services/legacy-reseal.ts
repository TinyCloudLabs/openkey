// TC-3554: one-time re-seal of every key sealed under the pre-move Phala root to the current root.
//
// Sealed material is AES-GCM under sha256(GetKey(path)). Phala's move changed the root behind getKey, so rows
// sealed before it only open under the epoch-0 root, which the key-recovery sidecar can read. This pass opens
// each such row once with the epoch-0 key, seals it again under the current key, and checks the result.
//
// Fail closed: the canary failing, a lost swap, a failed verification, or too many quarantined rows stops the
// pass with a LegacyResealError. The caller (apps/api boot) lets that end the process, so the API never
// listens on a half-migrated database. A few rows that cannot be opened at all are QUARANTINED instead: left
// exactly as they were (they were unusable before), reported by id and counted, and the API still starts.
// Nothing here logs addresses, paths or key material.
//
//  1. Each row's path comes from resolveSealingContext (the same rule every signer uses).
//  2. A row that already opens under the CURRENT key, and whose plaintext belongs to the row (address or
//     public key), is current. Re-running is a no-op, and needs no old root at all.
//  3. Otherwise it is pending. If there are pending rows, the old root is loaded (`openLegacy`: sidecar, pinned
//     root, mandatory canary) before ANY row is touched. The canary row is swapped last, so it is still
//     old-sealed whenever another row is pending.
//  4. Pre-verify, before the first write: every pending row is opened with the old key and checked against its
//     own address or public key (an anchor independent of Phala and of the sidecar). One that fails is
//     quarantined. More than max(3, 0.5% of rows) quarantined means the wrong key: fail closed. The canary
//     itself failing always fails closed.
//  5. Each verified row is sealed under the current key, re-opened and re-checked, and swapped with a
//     compare-and-swap on the ciphertext it read.
//  6. A final pass re-reads every row: current, or one of the quarantined.
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
  | 'reseal_verify_failed'
  | 'reseal_quarantine_limit';

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
  /** Called after each row is swapped. Counts only. The caller decides how often to log. */
  onProgress?: (progress: { done: number; pending: number; total: number }) => void;
  /** Old-key fetches in flight during pre-verify. Defaults to 4. */
  concurrency?: number;
}

/** Why a row was left untouched. Never includes key material. */
export type QuarantineReason = 'unreadable' | 'unopenable' | 'mismatch';
export interface ResealQuarantined {
  source: ResealSource;
  id: string;
  reason: QuarantineReason;
}

export interface ResealSummary {
  total: number;
  migrated: number;
  alreadyCurrent: number;
  /** Rows left exactly as they were: they open under neither key, or do not belong to themselves. */
  quarantined: ResealQuarantined[];
}

/** Old-key fetches in flight at once. The KMS rate limit behind the sidecar is unknown, so this stays small. */
const DEFAULT_CONCURRENCY = 4;

/** More quarantined rows than this means the wrong key, not a few bad rows: the boot fails closed. */
export function quarantineLimit(total: number): number {
  return Math.max(3, total * 0.005);
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

type State = 'current' | 'pending' | 'quarantined';
type Classified = { row: ResealRow; store: ResealStore; state: State; reason?: QuarantineReason };

/** Opens every row under the CURRENT key. Nothing is written and the old root is not involved. */
async function classify(stores: readonly ResealStore[], tee: ResealTee): Promise<Classified[]> {
  const out: Classified[] = [];
  for (const store of stores) {
    for (const row of await store.rows()) {
      let path: string;
      try {
        path = pathOf(row);
      } catch {
        out.push({ row, store, state: 'quarantined', reason: 'unreadable' });
        continue;
      }
      const key = await tee.deriveKey(path);
      try {
        const plaintext = await opens(row.sealed, key);
        if (plaintext === null) {
          out.push({ row, store, state: 'pending' });
        } else if (matches(row, plaintext)) {
          out.push({ row, store, state: 'current' });
        } else {
          // Opens under the current key but holds someone else's secret: not old, and not ours to rewrite.
          out.push({ row, store, state: 'quarantined', reason: 'mismatch' });
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
  const limit = quarantineLimit(rows.length);
  const isCanary = (entry: Classified) => entry.row.source === canary.source && entry.row.id === canary.id;
  const quarantined: ResealQuarantined[] = rows
    .filter((entry) => entry.state === 'quarantined')
    .map((entry) => ({ source: entry.row.source, id: entry.row.id, reason: entry.reason! }));
  const checkLimit = () => {
    if (quarantined.length > limit) throw new LegacyResealError('reseal_quarantine_limit');
  };
  const quarantine = (entry: Classified, reason: QuarantineReason) => {
    quarantined.push({ source: entry.row.source, id: entry.row.id, reason });
    checkLimit();
  };
  checkLimit();

  const canaryEntry = rows.find(isCanary);
  if (canaryEntry?.state === 'quarantined') throw new LegacyResealError('reseal_canary_not_pending', canaryEntry.row);

  const pending = rows.filter((entry) => entry.state === 'pending');
  const verified: { entry: Classified; key: Uint8Array }[] = [];
  const held: Uint8Array[] = []; // every old key fetched; all zeroed on the way out, however it ends
  let migrated = 0;
  try {
    if (pending.length > 0 && canaryEntry?.state === 'current') {
      // The canary is swapped last, so a current canary means an earlier pass finished every row it could open.
      // What is still pending was quarantined then. The old root cannot be proven without a pending canary:
      // leave these rows exactly as they are.
      for (const entry of pending) quarantine(entry, 'unopenable');
    } else if (pending.length > 0) {
      if (!canaryEntry) throw new LegacyResealError('reseal_canary_missing');

      // Old root, with its canary proven, before anything is written.
      const legacy = await options.openLegacy();

      // Pre-verify: open every pending row with the old key and check it belongs to itself, BEFORE the first
      // write. A row that fails is quarantined (the canary never is: it fails the boot). The fetch runs with a
      // small bounded concurrency; nothing is written during it, and any sidecar/KMS error is fatal: no new
      // fetch starts after the first failure, and every key already fetched is zeroed.
      const outcomes: ({ key: Uint8Array } | { reason: QuarantineReason })[] = new Array(pending.length);
      let failed: { error: unknown } | undefined;
      let next = 0;
      let bad = quarantined.length;
      const worker = async () => {
        while (!failed) {
          const index = next++;
          const entry = pending[index];
          if (!entry) return;
          try {
            const key = await legacy.legacyKey(pathOf(entry.row));
            held.push(key);
            const plaintext = await opens(entry.row.sealed, key);
            const reason: QuarantineReason | null = plaintext === null ? 'unopenable' : matches(entry.row, plaintext) ? null : 'mismatch';
            if (reason === null) {
              outcomes[index] = { key };
              continue;
            }
            key.fill(0);
            if (isCanary(entry)) throw new LegacyResealError(reason === 'unopenable' ? 'reseal_old_unseal_failed' : 'reseal_row_mismatch', entry.row);
            outcomes[index] = { reason };
            bad += 1;
            if (bad > limit) throw new LegacyResealError('reseal_quarantine_limit');
          } catch (error) {
            failed ??= { error };
            return;
          }
        }
      };
      const width = Math.max(1, Math.floor(options.concurrency ?? DEFAULT_CONCURRENCY));
      await Promise.all(Array.from({ length: Math.min(width, pending.length) }, worker));
      if (failed) throw failed.error;
      for (const [index, entry] of pending.entries()) {
        const outcome = outcomes[index]!;
        if ('key' in outcome) verified.push({ entry, key: outcome.key });
        else quarantine(entry, outcome.reason);
      }

      const ordered = [...verified.filter(({ entry }) => !isCanary(entry)), ...verified.filter(({ entry }) => isCanary(entry))];
      for (const [index, { entry, key }] of ordered.entries()) {
        const { row, store } = entry;
        const plaintext = await opens(row.sealed, key);
        if (plaintext === null) throw new LegacyResealError('reseal_old_unseal_failed', row);
        const path = pathOf(row);
        const newKey = await tee.deriveKey(path);
        try {
          const sealed = await seal(plaintext, newKey);
          const reopened = await opens(sealed, newKey);
          if (reopened !== plaintext || !matches(row, reopened)) throw new LegacyResealError('reseal_verify_failed', row);
          if (!(await store.swap(row, sealed))) throw new LegacyResealError('reseal_swap_failed', row);
        } finally {
          newKey.fill(0);
        }
        key.fill(0);
        migrated += 1;
        options.onProgress?.({ done: index + 1, pending: ordered.length, total: rows.length });
      }
    }
  } finally {
    for (const key of held) key.fill(0);
  }

  // Every row, re-read, must now open under the current key and belong to itself, or be a quarantined row.
  const after = await classify(stores, tee);
  const known = new Set(quarantined.map((q) => `${q.source}:${q.id}`));
  const stale = after.find((entry) => entry.state !== 'current' && !known.has(`${entry.row.source}:${entry.row.id}`));
  if (stale) throw new LegacyResealError('reseal_verify_failed', stale.row);
  return {
    total: after.length,
    migrated,
    alreadyCurrent: rows.filter((entry) => entry.state === 'current').length,
    quarantined,
  };
}
