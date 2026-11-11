import { expect, test } from 'bun:test';
import { combine } from 'shamir-secret-sharing';
import vector from './fixtures/escrow-shares-v1.json';
const escrowId = 'test-escrow-v1';

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
  const commitment = escrowKeyCommitment(key, escrowId);
  const shares = vector.sharesHex.map(hex => new Uint8Array(Buffer.from(hex, 'hex')));
  await expect(recoverEscrowKey([shares[0]!], commitment, escrowId)).rejects.toThrow();
  await expect(recoverEscrowKey([shares[0]!, shares[0]!], commitment, escrowId)).rejects.toThrow();
  const zero = shares[0]!.slice(); zero[32] = 0;
  await expect(recoverEscrowKey([zero, shares[1]!], commitment, escrowId)).rejects.toThrow();
  const tampered = shares[0]!.slice(); tampered[0] = tampered[0]! ^ 1;
  await expect(recoverEscrowKey([tampered, shares[1]!], commitment, escrowId)).rejects.toThrow();
  const otherKey = crypto.getRandomValues(new Uint8Array(32));
  const foreignShares = await splitEscrowKey(otherKey);
  const foreign = foreignShares.find(share => share[32] !== shares[2]![32])!;
  await expect(recoverEscrowKey([foreign, shares[2]!], commitment, escrowId)).rejects.toThrow();
  await expect(recoverEscrowKey([shares[0]!.slice(0, 32), shares[1]!], commitment, escrowId)).rejects.toThrow();
  await expect(recoverEscrowKey([shares[0]!, shares[1]!], 'invalid', escrowId)).rejects.toThrow();
  await expect(recoverEscrowKey([shares[0]!, shares[1]!], commitment, 'different-escrow')).rejects.toThrow();
});

test('random production split reconstructs from every pair', async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const shares = await splitEscrowKey(key);
  for (const [a, b] of [[0, 1], [0, 2], [1, 2]]) {
    expect(await recoverEscrowKey([shares[a!]!, shares[b!]!], escrowKeyCommitment(key, escrowId), escrowId)).toEqual(key);
  }
});

test('escrow-bound commitment matches the independent fixture', () => {
  expect(escrowKeyCommitment(new Uint8Array(Buffer.from(vector.secretHex, 'hex')), vector.escrowId)).toBe(vector.commitmentHex);
});
