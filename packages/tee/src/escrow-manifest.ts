import { createHash } from 'node:crypto';
import type { EscrowHeader } from './escrow-header';
import { escrowMaterialLength, type EscrowTransform } from './escrow-transform';

export interface EscrowRecordManifestEntry {
  table: string; rowId: string; owner: string | null; path: string; purpose: string;
  version: number; transform: EscrowTransform; expectedIdentity: string; ciphertextChecksum: string;
}
const text = (value: unknown) => {
  if (typeof value !== 'string' || !value || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) throw new Error('Invalid record manifest');
};
const identity = (p: { path: string; purpose: string; version: number; transform: string }) => JSON.stringify([p.path, p.purpose, p.version, p.transform]);

/** Private snapshot artifact. Holder bundles carry its hash, never these rows. */
export function encodeRecordManifest(entries: readonly EscrowRecordManifestEntry[], paths: EscrowHeader['paths']): Uint8Array {
  const expected = new Map(paths.map(p => [identity(p), p.expectedCount]));
  const counts = new Map(paths.map(p => [identity(p), 0]));
  const rows = new Set<string>();
  if (expected.size !== paths.length) throw new Error('Duplicate manifest path');
  const tuples = entries.map(entry => {
    for (const value of [entry.table, entry.rowId, entry.path, entry.purpose, entry.expectedIdentity]) text(value);
    if (entry.owner !== null) text(entry.owner);
    if (!Number.isSafeInteger(entry.version) || entry.version < 0 || Object.is(entry.version, -0)
      || typeof entry.ciphertextChecksum !== 'string' || !/^[a-f0-9]{64}$/.test(entry.ciphertextChecksum)) throw new Error('Invalid record manifest');
    escrowMaterialLength(entry.transform);
    const rowId = JSON.stringify([entry.table, entry.rowId]);
    const pathId = identity(entry);
    if (rows.has(rowId) || !expected.has(pathId)) throw new Error('Invalid manifest coverage');
    rows.add(rowId); counts.set(pathId, counts.get(pathId)! + 1);
    return [entry.table, entry.rowId, entry.owner, entry.path, entry.purpose, entry.version, entry.transform, entry.expectedIdentity, entry.ciphertextChecksum];
  }).sort((a, b) => JSON.stringify(a) < JSON.stringify(b) ? -1 : JSON.stringify(a) > JSON.stringify(b) ? 1 : 0);
  for (const [id, count] of expected) if (counts.get(id) !== count) throw new Error('Incomplete record manifest');
  return new TextEncoder().encode(JSON.stringify(['tinycloud/escrow/record-manifest', 1, tuples]));
}

export function recordManifestHash(entries: readonly EscrowRecordManifestEntry[], paths: EscrowHeader['paths']): string {
  return createHash('sha256').update(encodeRecordManifest(entries, paths)).digest('hex');
}
