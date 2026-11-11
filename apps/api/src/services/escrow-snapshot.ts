import { createHash } from 'node:crypto';
import { buildOpenKeyInventory, type OpenKeySnapshotRows } from './escrow-inventory';

export interface EscrowSqlTransaction {
  $executeRawUnsafe(query: string): Promise<number>;
  $queryRawUnsafe<T>(query: string): Promise<T>;
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
}) => Promise<T>): Promise<T> {
  return database.$transaction(async tx => {
    // SHARE blocks INSERT/UPDATE/DELETE (ROW EXCLUSIVE), including new paths.
    // Fixed order across maintenance operations avoids table-order inversion.
    await tx.$executeRawUnsafe('LOCK TABLE "ethereum_keys", "nostr_keys", "user_encryption_key" IN SHARE MODE');
    const marker = await tx.$queryRawUnsafe<{ snapshot: string }[]>('SELECT txid_current_snapshot()::text AS snapshot');
    if (marker.length !== 1 || !/^\d+:\d+:(?:\d+(?:,\d+)*)?$/.test(marker[0]!.snapshot)) throw new Error('Invalid database snapshot');
    const ethereum = await tx.$queryRawUnsafe<OpenKeySnapshotRows['ethereum']>('SELECT "id", "userId", "sealingContext", "keyType"::text AS "keyType", "sealedBlob", "address" FROM "ethereum_keys" ORDER BY "id"');
    const nostr = await tx.$queryRawUnsafe<OpenKeySnapshotRows['nostr']>('SELECT "id", "userId", "sealingContext", "sealedSecret", "pubkeyHex" FROM "nostr_keys" ORDER BY "id"');
    const legacy = await tx.$queryRawUnsafe<OpenKeySnapshotRows['legacy']>('SELECT "id", "userId", "sealedPrivateKey", "publicKey" FROM "user_encryption_key" ORDER BY "id"');
    const rows = { ethereum, nostr, legacy };
    const inventory = buildOpenKeyInventory(rows);
    const ciphertextSnapshotHash = createHash('sha256').update(JSON.stringify(rows)).digest('hex');
    return operation({ tx, rows, inventory, snapshotId: marker[0]!.snapshot, ciphertextSnapshotHash });
  }, { isolationLevel: 'RepeatableRead', maxWait: 10_000, timeout: 300_000 });
}
