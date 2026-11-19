import { createHash } from 'node:crypto';
import { ensureEip55 } from '@tinycloud/node-sdk-wasm';
import type { Prisma } from '@openkey/db';

/**
 * SHA-256 (hex) of the owner DID a key's address has on a TinyCloud node. The DID is built from the EIP-55
 * form of the address, as delegate.ts builds it and as the node canonicalizes it, always on chain 1.
 */
export function ownerDigestFor(address: string): string {
  const did = `did:pkh:eip155:1:${ensureEip55(address)}`;
  return createHash('sha256').update(did).digest('hex');
}

/**
 * Records that an account was deleted: one row holding the owner digest of each of its keys, and nothing that
 * identifies the account. Call it inside the transaction that deletes the keys, with the key rows read in that
 * transaction before they are deleted, so the receipt exists exactly when the keys are gone. Writes nothing and
 * returns false when there were no keys.
 */
export async function recordAccountDeletionReceipt(
  transaction: Pick<Prisma.TransactionClient, 'accountDeletionReceipt'>,
  keys: readonly { address: string }[],
): Promise<boolean> {
  const ownerDigests = [...new Set(keys.map((key) => ownerDigestFor(key.address)))].sort();
  if (ownerDigests.length === 0) return false;
  await transaction.accountDeletionReceipt.create({ data: { ownerDigests } });
  return true;
}
