import { createHash, createDecipheriv, createPrivateKey, createPublicKey, timingSafeEqual } from 'node:crypto';
import { privateKeyToAddress } from 'viem/accounts';
import { deriveNostrPubkey } from '@openkey/tee';
import type { EscrowInventoryRow, InventoryPath } from './escrow-inventory';

export interface InventoryMaterial { path: string; purpose: string; version: number; key: Uint8Array }
const identity = (p: { path: string; purpose: string; version: number }) => JSON.stringify([p.path, p.purpose, p.version]);

/** Internal snapshot validator. Returns counts only; no plaintext leaves this process. */
export function validateOpenKeySnapshot(records: readonly EscrowInventoryRow[], paths: readonly InventoryPath[], material: readonly InventoryMaterial[]) {
  const expected = new Map(paths.map(p => [identity(p), p]));
  const keys = new Map(material.map(k => [identity(k), k.key]));
  if (expected.size !== paths.length || keys.size !== material.length) throw new Error('Invalid validation inventory');
  const counts = new Map(paths.map(p => [identity(p), 0]));
  const rowIds = new Set<string>();
  for (const row of records) {
    const id = identity(row);
    const path = expected.get(id); const key = keys.get(id);
    const rowId = JSON.stringify([row.table, row.id]);
    if (!path || !key || key.length !== 32 || row.version !== 0 || path.transform !== 'sha256-getkey'
      || rowIds.has(rowId) || row.transform !== path.transform) throw new Error('Invalid validation row');
    rowIds.add(rowId);
    if (createHash('sha256').update(row.blob, 'utf8').digest('hex') !== row.ciphertextChecksum) throw new Error('Snapshot ciphertext mismatch');
    const blob = Buffer.from(row.blob, 'base64');
    if (blob.length < 28 || blob.toString('base64') !== row.blob) throw new Error('Invalid validation ciphertext');
    const decipher = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
    decipher.setAuthTag(blob.subarray(12, 28));
    const partial = decipher.update(blob.subarray(28));
    let plaintext: Buffer | undefined;
    try {
      plaintext = Buffer.concat([partial, decipher.final()]);
      if (row.purpose === 'ethereum' && row.table === 'ethereum_keys') {
        const address = privateKeyToAddress(plaintext.toString('utf8') as `0x${string}`);
        if (address.toLowerCase() !== row.expectedIdentity.toLowerCase()) throw new Error('Escrow identity mismatch');
      } else if (row.purpose === 'nostr' && row.table === 'nostr_keys') {
        if (deriveNostrPubkey(plaintext.toString('utf8')) !== row.expectedIdentity) throw new Error('Escrow identity mismatch');
      } else if (row.purpose === 'legacy-user-encryption' && row.table === 'user_encryption_key') {
        const privateKey = createPrivateKey({ key: plaintext, format: 'pem' });
        if (privateKey.asymmetricKeyType !== 'rsa') throw new Error('Invalid legacy identity');
        const actual = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
        const stored = createPublicKey(row.expectedIdentity).export({ format: 'der', type: 'spki' });
        if (actual.length !== stored.length || !timingSafeEqual(actual, stored)) throw new Error('Escrow identity mismatch');
      } else throw new Error('Unsupported escrow purpose');
      counts.set(id, counts.get(id)! + 1);
    } finally {
      partial.fill(0); plaintext?.fill(0);
    }
  }
  const expectedMaterial = paths.filter(p => p.expectedCount > 0);
  if (keys.size !== expectedMaterial.length || expectedMaterial.some(p => !keys.has(identity(p)))) throw new Error('Invalid validation key coverage');
  return paths.map(p => {
    const validatedCount = counts.get(identity(p))!;
    if (validatedCount !== p.expectedCount) throw new Error('Incomplete validation');
    return { path: p.path, purpose: p.purpose, version: p.version, validatedCount };
  });
}
