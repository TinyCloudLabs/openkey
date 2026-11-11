import { expect, test } from 'bun:test';
import { combine } from 'shamir-secret-sharing';
import vector from './fixtures/escrow-shares-v1.json';

// Synthetic public interoperability fixture; never use its deterministic entropy for escrow.
test('Privy reconstructs the common field/layout vector from every pair', async () => {
  const shares = vector.sharesHex.map(hex => new Uint8Array(Buffer.from(hex, 'hex')));
  for (const [a, b] of [[0, 1], [0, 2], [1, 2]]) {
    expect(Buffer.from(await combine([shares[a!]!, shares[b!]!])).toString('hex')).toBe(vector.secretHex);
  }
});

import { escrowKeyCommitment, recoverEscrowKey, splitEscrowKey } from '../src/escrow-shares';

test('recovery rejects single, zero-index, duplicate, tampered and foreign shares', async () => {
  const key = new Uint8Array(Buffer.from(vector.secretHex, 'hex'));
  const commitment = escrowKeyCommitment(key);
  const shares = vector.sharesHex.map(hex => new Uint8Array(Buffer.from(hex, 'hex')));
  await expect(recoverEscrowKey([shares[0]!], commitment)).rejects.toThrow();
  await expect(recoverEscrowKey([shares[0]!, shares[0]!], commitment)).rejects.toThrow();
  const zero = shares[0]!.slice(); zero[32] = 0;
  await expect(recoverEscrowKey([zero, shares[1]!], commitment)).rejects.toThrow();
  const tampered = shares[0]!.slice(); tampered[0] = tampered[0]! ^ 1;
  await expect(recoverEscrowKey([tampered, shares[1]!], commitment)).rejects.toThrow();
  const foreign = shares[0]!.slice(); foreign[1] = foreign[1]! ^ 1;
  await expect(recoverEscrowKey([foreign, shares[2]!], commitment)).rejects.toThrow();
});

test('random production split reconstructs from every pair', async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const shares = await splitEscrowKey(key);
  for (const [a, b] of [[0, 1], [0, 2], [1, 2]]) {
    expect(await recoverEscrowKey([shares[a!]!, shares[b!]!], escrowKeyCommitment(key))).toEqual(key);
  }
});
