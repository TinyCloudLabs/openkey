// TC-2376: only the redeemer that actually deletes the code row may take it. Single-connection PGlite
// cannot interleave two redeems, so the guard is proven here with a transaction whose delete loses.
import { describe, expect, test } from 'bun:test';
import type { PrismaClient } from '@openkey/db';
import { createPrismaDelegationCodeStore } from '../routes/delegation-codes';

const delegation = { delegationCid: 'bafy-delegation' };
const now = new Date('2026-11-03T12:00:00Z');

function transaction(deleted: number) {
  const calls: string[] = [];
  const tx = {
    delegationCodeClaim: {
      findUnique: async () => null,
      upsert: async () => { calls.push('claim row written'); },
    },
    delegationCode: {
      findFirst: async () => ({ code: 'aaaa-bbbb', delegation, expiresAt: new Date(now.getTime() + 60_000) }),
      deleteMany: async () => ({ count: deleted }),
    },
  };
  const prisma = { $transaction: async <T>(run: (inner: typeof tx) => Promise<T>) => run(tx) } as unknown as PrismaClient;
  return { prisma, calls };
}

describe('claiming a short code takes it only for the redeemer that deleted the row', () => {
  test('a redeemer whose delete removed nothing gets nothing and writes no claim', async () => {
    const { prisma, calls } = transaction(0);
    expect(await createPrismaDelegationCodeStore(prisma).claim('aaaa-bbbb', 'claim-hash', now)).toBeNull();
    expect(calls).toEqual([]);
  });

  test('the redeemer whose delete removed the row gets the delegation and its claim is written', async () => {
    const { prisma, calls } = transaction(1);
    expect(await createPrismaDelegationCodeStore(prisma).claim('aaaa-bbbb', 'claim-hash', now)).toEqual({ delegation });
    expect(calls).toEqual(['claim row written']);
  });
});
