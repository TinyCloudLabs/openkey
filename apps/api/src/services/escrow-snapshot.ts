import { openKeyDbSnapshotHash } from './escrow-db-encoding';
import { buildOpenKeyInventory, type OpenKeySnapshotRows } from './escrow-inventory';

export interface EscrowSqlTransaction {
  $executeRawUnsafe(query: string, ...values: unknown[]): Promise<number>;
  $queryRawUnsafe<T>(query: string, ...values: unknown[]): Promise<T>;
}
export interface EscrowSqlDatabase {
  $transaction<T>(operation: (tx: EscrowSqlTransaction) => Promise<T>, options: { isolationLevel: 'RepeatableRead'; maxWait: number; timeout: number }): Promise<T>;
}

/** No URL discovery or client construction: caller supplies the authorized database. */
export async function withFencedOpenKeySnapshot<T>(database: EscrowSqlDatabase, operation: (snapshot: {
  tx: EscrowSqlTransaction;
  rows: OpenKeySnapshotRows;
  inventory: ReturnType<typeof buildOpenKeyInventory>;
  snapshotId: string;
  ciphertextSnapshotHash: string;
}) => Promise<T>, beforeRead?: (tx: EscrowSqlTransaction) => Promise<void>, exclusive = false): Promise<T> {
  return database.$transaction(async tx => {
    // SHARE blocks INSERT/UPDATE/DELETE (ROW EXCLUSIVE), including new paths.
    // Fixed order across maintenance operations avoids table-order inversion.
    await tx.$executeRawUnsafe(exclusive === true
      ? 'LOCK TABLE "ethereum_keys", "nostr_keys", "user_encryption_key" IN EXCLUSIVE MODE'
      : 'LOCK TABLE "ethereum_keys", "nostr_keys", "user_encryption_key" IN SHARE MODE');
    if (beforeRead) await beforeRead(tx);
    const marker = await tx.$queryRawUnsafe<{ snapshot: string }[]>('SELECT txid_current_snapshot()::text AS snapshot');
    if (marker.length !== 1 || !/^\d+:\d+:(?:\d+(?:,\d+)*)?$/.test(marker[0]!.snapshot)) throw new Error('Invalid database snapshot');
    const rows = await readOpenKeySnapshotRows(tx);
    const inventory = buildOpenKeyInventory(rows);
    const ciphertextSnapshotHash = openKeyDbSnapshotHash(rows);
    return operation({ tx, rows, inventory, snapshotId: marker[0]!.snapshot, ciphertextSnapshotHash });
  }, { isolationLevel: 'RepeatableRead', maxWait: 10_000, timeout: 300_000 });
}

/** Complete fixed-column reads, for post-write verification in the same fenced tx. */
export async function readOpenKeySnapshotRows(tx: EscrowSqlTransaction): Promise<OpenKeySnapshotRows> {
  const ethereum = await tx.$queryRawUnsafe<OpenKeySnapshotRows['ethereum']>('SELECT "id", "userId", "sealingContext", "keyType"::text AS "keyType", "sealedBlob", "address", "publicKey", "isCanonicalTinyCloud", "keyIndex", "label", "archivedAt", "createdAt" FROM "ethereum_keys" ORDER BY "id"');
  const nostr = await tx.$queryRawUnsafe<OpenKeySnapshotRows['nostr']>('SELECT "id", "userId", "sealingContext", "sealedSecret", "pubkeyHex", "npub", "label", "revokedAt", "createdAt" FROM "nostr_keys" ORDER BY "id"');
  const legacy = await tx.$queryRawUnsafe<OpenKeySnapshotRows['legacy']>('SELECT "id", "userId", "sealedPrivateKey", "publicKey", "createdAt" FROM "user_encryption_key" ORDER BY "id"');
  const rows = { ethereum, nostr, legacy };
  return rows;
}
