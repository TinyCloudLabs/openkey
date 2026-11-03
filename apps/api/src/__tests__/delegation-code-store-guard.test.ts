// TC-2376: only the redeemer that actually deletes the code row may take it. Single-connection PGlite
// cannot interleave two redeems, so the guard is proven here with a transaction whose delete loses.
import { describe, expect, test } from 'bun:test';
import type { PrismaClient } from '@openkey/db';
import { createPrismaDelegationCodeStore } from '../routes/delegation-codes';

const delegation = { delegationCid: 'bafy-delegation' };
const now = new Date('2026-11-03T12:00:00Z');

function transaction(deleted: number) {
  const calls: unknown[] = [];
  const tx = {
    delegationCodeClaim: {
      findUnique: async () => null,
      upsert: async (args: { create: unknown }) => { calls.push({ claimed: args.create }); },
    },
    delegationCode: {
      findFirst: async () => ({ code: 'aaaa-bbbb', delegation, expiresAt: new Date(now.getTime() + 60_000) }),
      deleteMany: async (args: unknown) => { calls.push({ deleted: args }); return { count: deleted }; },
    },
  };
  const prisma = { $transaction: async <T>(run: (inner: typeof tx) => Promise<T>) => run(tx) } as unknown as PrismaClient;
  return { prisma, calls };
}

describe('claiming a short code takes it only for the redeemer that deleted the row', () => {
  test('a redeemer whose delete removed nothing gets nothing and writes no claim', async () => {
    const { prisma, calls } = transaction(0);
    expect(await createPrismaDelegationCodeStore(prisma).claim('aaaa-bbbb', 'claim-hash', now)).toBeNull();
    expect(calls).toEqual([{ deleted: { where: { code: 'aaaa-bbbb' } } }]);
  });

  test('the redeemer whose delete removed the row gets the delegation and its claim is written', async () => {
    const { prisma, calls } = transaction(1);
    expect(await createPrismaDelegationCodeStore(prisma).claim('aaaa-bbbb', 'claim-hash', now)).toEqual({ delegation });
    expect(calls).toEqual([
      { deleted: { where: { code: 'aaaa-bbbb' } } },
      { claimed: { code: 'aaaa-bbbb', claimHash: 'claim-hash', delegation, redeemedAt: now, acknowledgedAt: null } },
    ]);
  });
});
