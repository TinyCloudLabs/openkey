import { createHash } from 'node:crypto';

// Fixed v1 column order and types, independent of driver property order.
const tables = [
  ['ethereum_keys', 'ethereum', [
    ['id', 's'], ['userId', 's?'], ['address', 's'], ['publicKey', 's'], ['sealedBlob', 's?'], ['sealingContext', 's?'],
    ['keyType', 's'], ['isCanonicalTinyCloud', 'b'], ['keyIndex', 'i'], ['label', 's?'], ['archivedAt', 'd?'], ['createdAt', 'd'],
  ]],
  ['nostr_keys', 'nostr', [
    ['id', 's'], ['userId', 's'], ['label', 's?'], ['pubkeyHex', 's'], ['npub', 's'], ['sealedSecret', 's'], ['sealingContext', 's'], ['revokedAt', 'd?'], ['createdAt', 'd'],
  ]],
  ['user_encryption_key', 'legacy', [
    ['id', 's'], ['userId', 's'], ['publicKey', 's'], ['sealedPrivateKey', 's'], ['createdAt', 'd'],
  ]],
] as const;

export function encodeOpenKeyDbSnapshot(input: unknown): Uint8Array {
  if (!input || typeof input !== 'object') throw new Error('Invalid DB snapshot');
  const source = input as Record<string, unknown>;
  const result = tables.map(([table, property, columns]) => {
    const rows = source[property];
    if (!Array.isArray(rows)) throw new Error('Missing DB snapshot table');
    const ids = new Set<string>();
    const tuples = rows.map(row => {
      if (!row || typeof row !== 'object' || typeof row.id !== 'string' || !row.id || ids.has(row.id)) throw new Error('Invalid DB snapshot row');
      ids.add(row.id);
      return columns.map(([field, type]) => {
        const value = row[field];
        if (value === null && type.endsWith('?')) return null;
        if (type.startsWith('s') && typeof value === 'string'
          && !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) return value;
        if (type === 'b' && typeof value === 'boolean') return value;
        if (type === 'i' && Number.isSafeInteger(value) && !Object.is(value, -0)) return value;
        if (type.startsWith('d') && value instanceof Date && Number.isFinite(value.getTime())) return value.toISOString();
        throw new Error('Invalid DB snapshot column');
      });
    }).sort((a, b) => (a[0] as string) < (b[0] as string) ? -1 : (a[0] as string) > (b[0] as string) ? 1 : 0);
    return [table, tuples];
  });
  return new TextEncoder().encode(JSON.stringify(['tinycloud/escrow/db-snapshot', 1, result]));
}
export function openKeyDbSnapshotHash(input: unknown): string {
  return createHash('sha256').update(encodeOpenKeyDbSnapshot(input)).digest('hex');
}
