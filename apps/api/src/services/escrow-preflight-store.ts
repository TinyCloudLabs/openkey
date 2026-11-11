import { createHash } from 'node:crypto';
import { freezeEscrowPreflightPolicy, type ExportPolicy } from '@openkey/tee';
import type { EscrowSqlTransaction } from './escrow-snapshot';

export interface StoredEscrowPreflight {
  policy: ExportPolicy;
  recordManifestUtf8: string;
  dbSnapshotUtf8: string;
}

/** Called inside the fenced preflight transaction; stores no plaintext key material. */
export async function storeEscrowPreflight(tx: EscrowSqlTransaction, input: StoredEscrowPreflight): Promise<string> {
  const copied = structuredClone(input);
  const frozen = await freezeEscrowPreflightPolicy(copied.policy);
  if (Date.parse(frozen.header.expiresAt) <= Date.now()
    || createHash('sha256').update(copied.recordManifestUtf8).digest('hex') !== frozen.header.recordManifestHash
    || createHash('sha256').update(copied.dbSnapshotUtf8).digest('hex') !== frozen.header.dbSnapshotHash) throw new Error('Invalid stored preflight');
  const rows = await tx.$executeRawUnsafe(
    'INSERT INTO "escrow_preflight" ("policyHash", "nonce", "expiresAt", "payload") VALUES ($1, $2, $3::timestamptz, $4::jsonb)',
    frozen.hash, frozen.header.nonce, frozen.header.expiresAt, JSON.stringify(copied),
  );
  if (rows !== 1) throw new Error('Preflight not stored');
  return frozen.hash;
}

/** Only the server reads this private artifact. Never return payload through the route. */
export async function loadEscrowPreflight(database: EscrowSqlTransaction, policyHash: string): Promise<StoredEscrowPreflight> {
  if (typeof policyHash !== 'string' || !/^[a-f0-9]{64}$/.test(policyHash)) throw new Error('Invalid preflight hash');
  const rows = await database.$queryRawUnsafe<{ payload: StoredEscrowPreflight }[]>(
    'SELECT "payload" FROM "escrow_preflight" WHERE "policyHash" = $1 AND "consumedAt" IS NULL AND "expiresAt" > clock_timestamp()', policyHash,
  );
  if (rows.length !== 1) throw new Error('Preflight unavailable');
  const result = structuredClone(rows[0]!.payload);
  if ((await freezeEscrowPreflightPolicy(result.policy)).hash !== policyHash
    || createHash('sha256').update(result.recordManifestUtf8).digest('hex') !== result.policy.recordManifestHash
    || createHash('sha256').update(result.dbSnapshotUtf8).digest('hex') !== result.policy.dbSnapshotHash) throw new Error('Stored preflight mismatch');
  return result;
}
