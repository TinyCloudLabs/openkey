import { createHash } from 'node:crypto';
import { sealingKid } from '@openkey/tee';
import { resolveSealingContext } from './key-sealing';

export interface EscrowInventoryRow {
  table: 'ethereum_keys' | 'nostr_keys' | 'user_encryption_key';
  id: string;
  owner: string | null;
  path: string;
  purpose: 'ethereum' | 'nostr' | 'legacy-user-encryption';
  version: number;
  transform: 'sha256-getkey';
  expectedIdentity: string;
  ciphertextChecksum: string;
  blob: string;
}
export interface OpenKeySnapshotRows {
  ethereum: readonly { id: string; userId: string | null; sealingContext: string | null; keyType: string; sealedBlob: string | null; address: string }[];
  nostr: readonly { id: string; userId: string; sealingContext: string; sealedSecret: string; pubkeyHex: string }[];
  legacy: readonly { id: string; userId: string; sealedPrivateKey: string; publicKey: string }[];
}
export interface InventoryPath {
  path: string; purpose: string; version: number; transform: 'sha256-getkey'; expectedCount: number;
}

function required(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 4096) throw new Error('Invalid escrow inventory');
}

/** Consumes complete table reads from one fenced snapshot, including archived/orphan rows. */
export function buildOpenKeyInventory(snapshot: OpenKeySnapshotRows): { records: EscrowInventoryRow[]; paths: InventoryPath[] } {
  if (!Array.isArray(snapshot.ethereum) || !Array.isArray(snapshot.nostr) || !Array.isArray(snapshot.legacy)) throw new Error('Missing escrow table');
  const records: EscrowInventoryRow[] = [];
  const rowIds = new Set<string>();
  const legacyUsers = new Set<string>();
  const add = (row: Omit<EscrowInventoryRow, 'ciphertextChecksum' | 'transform'>) => {
    required(row.id); required(row.path); required(row.blob); required(row.expectedIdentity);
    if (row.owner !== null) required(row.owner);
    const identity = JSON.stringify([row.table, row.id]);
    if (rowIds.has(identity)) throw new Error('Duplicate escrow record');
    rowIds.add(identity);
    records.push({ ...row, transform: 'sha256-getkey', ciphertextChecksum: createHash('sha256').update(row.blob, 'utf8').digest('hex') });
  };
  for (const row of snapshot.ethereum) {
    if (row.keyType === 'EXTERNAL') {
      if (row.sealedBlob !== null) throw new Error('Unexpected external ciphertext');
      continue;
    }
    if (row.keyType !== 'MANAGED' || !row.sealedBlob || !/^0x[0-9a-fA-F]{40}$/.test(row.address)) throw new Error('Invalid managed escrow row');
    if (row.sealingContext === null && (typeof row.userId !== 'string' || /[\/{}\u0000]/.test(row.userId))) throw new Error('Invalid legacy key owner');
    const path = resolveSealingContext(row);
    add({ table: 'ethereum_keys', id: row.id, owner: row.userId, path, purpose: 'ethereum', version: sealingKid(row.sealedBlob), expectedIdentity: row.address.toLowerCase(), blob: row.sealedBlob });
  }
  for (const row of snapshot.nostr) {
    required(row.userId);
    if (!/^[a-f0-9]{64}$/.test(row.pubkeyHex)) throw new Error('Invalid Nostr escrow row');
    const path = resolveSealingContext(row);
    add({ table: 'nostr_keys', id: row.id, owner: row.userId, path, purpose: 'nostr', version: sealingKid(row.sealedSecret), expectedIdentity: row.pubkeyHex, blob: row.sealedSecret });
  }
  for (const row of snapshot.legacy) {
    required(row.userId);
    // Concrete legacy user ids cannot inject a different path or the empty template.
    if (/[\/{}\u0000]/.test(row.userId) || legacyUsers.has(row.userId)) throw new Error('Invalid legacy escrow owner');
    legacyUsers.add(row.userId);
    if (sealingKid(row.sealedPrivateKey) !== 0) throw new Error('Unsupported legacy sealing version');
    add({ table: 'user_encryption_key', id: row.id, owner: row.userId, path: `openkey/user/${row.userId}/encryption`, purpose: 'legacy-user-encryption', version: 0, expectedIdentity: row.publicKey, blob: row.sealedPrivateKey });
  }
  const paths = new Map<string, InventoryPath>();
  for (const record of records) {
    // Only generation zero is currently backed by the deployed production provider.
    if (record.version !== 0) throw new Error('Unsupported escrow sealing generation');
    const id = JSON.stringify([record.path, record.purpose, record.version, record.transform]);
    const path = paths.get(id);
    if (path) path.expectedCount++;
    else paths.set(id, { path: record.path, purpose: record.purpose, version: record.version, transform: record.transform, expectedCount: 1 });
  }
  if (snapshot.legacy.length === 0) {
    paths.set('legacy-empty', { path: 'openkey/user/{userId}/encryption', purpose: 'legacy-user-encryption-empty', version: 0, transform: 'sha256-getkey', expectedCount: 0 });
  }
  const result = [...paths.values()];
  if (!result.some(p => p.purpose === 'legacy-user-encryption' || p.purpose === 'legacy-user-encryption-empty')) throw new Error('Missing legacy inventory');
  return { records, paths: result };
}
