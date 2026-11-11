import { createHash } from 'node:crypto';
import { freezeEscrowPreflightPolicy, type ExportPolicy } from '@openkey/tee';
import type { EscrowSqlTransaction } from './escrow-snapshot';

export interface StoredEscrowPreflight {
  policy: ExportPolicy;
  recordManifestUtf8: string;
  dbSnapshotUtf8: string;
}

function assertNulFree(value: unknown): void {
  if (typeof value === 'string') {
    if (value.includes('\0')) throw new Error('Invalid preflight string');
  } else if (Array.isArray(value)) {
    for (const entry of value) assertNulFree(entry);
  } else if (value && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) { assertNulFree(key); assertNulFree(entry); }
  }
}

/** Erase expired private artifacts; retain hash, nonce and times for audit. */
export async function sweepExpiredEscrowPreflights(database: EscrowSqlTransaction): Promise<void> {
  await database.$executeRawUnsafe('UPDATE public."escrow_preflight" SET "payload" = NULL WHERE "expiresAt" <= pg_catalog.clock_timestamp() AND "payload" IS NOT NULL');
}

/** Called inside the fenced preflight transaction; stores no plaintext key material. */
export async function storeEscrowPreflight(tx: EscrowSqlTransaction, input: StoredEscrowPreflight): Promise<string> {
  const copied = structuredClone(input);
  assertNulFree(copied);
  assertNulFree(JSON.parse(copied.recordManifestUtf8));
  assertNulFree(JSON.parse(copied.dbSnapshotUtf8));
  const frozen = await freezeEscrowPreflightPolicy(copied.policy);
  if (Date.parse(frozen.header.expiresAt) <= Date.now()
    || createHash('sha256').update(copied.recordManifestUtf8).digest('hex') !== frozen.header.recordManifestHash
    || createHash('sha256').update(copied.dbSnapshotUtf8).digest('hex') !== frozen.header.dbSnapshotHash) throw new Error('Invalid stored preflight');
  await sweepExpiredEscrowPreflights(tx);
  const rows = await tx.$executeRawUnsafe(
    'INSERT INTO public."escrow_preflight" ("policyHash", "nonce", "expiresAt", "payload") VALUES ($1, $2, $3::pg_catalog.timestamptz, $4::pg_catalog.jsonb)',
    frozen.hash, frozen.header.nonce, frozen.header.expiresAt, JSON.stringify(copied),
  );
  if (rows !== 1) throw new Error('Preflight not stored');
  return frozen.hash;
}

/** Only the server reads this private artifact. Never return payload through the route. */
export async function loadEscrowPreflight(database: EscrowSqlTransaction, policyHash: string): Promise<StoredEscrowPreflight> {
  if (typeof policyHash !== 'string' || !/^[a-f0-9]{64}$/.test(policyHash)) throw new Error('Invalid preflight hash');
  await sweepExpiredEscrowPreflights(database);
  const rows = await database.$queryRawUnsafe<{ payload: StoredEscrowPreflight }[]>(
    'SELECT "payload" FROM public."escrow_preflight" WHERE "policyHash" = $1 AND "consumedAt" IS NULL AND "expiresAt" > pg_catalog.clock_timestamp() AND "payload" IS NOT NULL', policyHash,
  );
  if (rows.length !== 1) throw new Error('Preflight unavailable');
  const result = structuredClone(rows[0]!.payload);
  assertNulFree(result);
  if ((await freezeEscrowPreflightPolicy(result.policy)).hash !== policyHash
    || createHash('sha256').update(result.recordManifestUtf8).digest('hex') !== result.policy.recordManifestHash
    || createHash('sha256').update(result.dbSnapshotUtf8).digest('hex') !== result.policy.dbSnapshotHash) throw new Error('Stored preflight mismatch');
  return result;
}
