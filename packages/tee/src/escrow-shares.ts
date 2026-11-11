import { createHash, timingSafeEqual } from 'node:crypto';
import { combine, split } from 'shamir-secret-sharing';

/** Internal enclave memory only. Never serialize returned shares outside HPKE. */
export async function splitEscrowKey(key: Uint8Array): Promise<Uint8Array[]> {
  if (key.length !== 32) throw new Error('Invalid escrow key');
  return split(key, 3, 2);
}

export function escrowKeyCommitment(key: Uint8Array, escrowId: string): string {
  if (key.length !== 32) throw new Error('Invalid escrow key');
  const id = Buffer.from(escrowId, 'utf8');
  if (id.length === 0 || id.length > 1024) throw new Error('Invalid escrow id');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(id.length);
  return createHash('sha256').update('tinycloud/escrow/content-key/v1\0').update(length).update(id).update(key).digest('hex');
}

/** Caller must authenticate each HPKE envelope and its header binding first. */
export async function recoverEscrowKey(shares: readonly Uint8Array[], commitment: string, escrowId: string): Promise<Uint8Array> {
  if (shares.length !== 2 || !/^[a-f0-9]{64}$/.test(commitment)) throw new Error('Invalid escrow recovery');
  const seen = new Set<number>();
  for (const share of shares) {
    const x = share[32];
    if (share.length !== 33 || !x || seen.has(x)) throw new Error('Invalid escrow share');
    seen.add(x);
  }
  const key = await combine([...shares]);
  if (!timingSafeEqual(Buffer.from(escrowKeyCommitment(key, escrowId), 'hex'), Buffer.from(commitment, 'hex'))) {
    key.fill(0);
    throw new Error('Escrow commitment mismatch');
  }
  return key;
}
