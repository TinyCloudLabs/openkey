import type { PrismaClient } from '@openkey/db';
import type { EscrowAuthorizationStore } from './escrow-approval';

/** Explicit client only; the one immutable ledger row is both nonce and audit record. */
export function createEscrowAuthorizationStore(prisma: Pick<PrismaClient, '$transaction'>): EscrowAuthorizationStore {
  return {
    consume: request => prisma.$transaction(async tx => {
      // Global serialization covers rate checks across processes and different nonces.
      await tx.$queryRawUnsafe('SELECT pg_advisory_xact_lock(2823, 1)::text AS lock');
      const validity = await tx.$queryRawUnsafe<{ valid: boolean }[]>('SELECT clock_timestamp() < $1::timestamptz AS valid', request.expiresAt);
      if (validity.length !== 1 || validity[0]!.valid !== true) throw new Error('Escrow approval expired');
      const recent = await tx.$queryRawUnsafe<{ count: bigint }[]>('SELECT count(*) AS count FROM "escrow_authorization" WHERE "createdAt" > CURRENT_TIMESTAMP - INTERVAL \'1 hour\'');
      if (recent.length !== 1 || recent[0]!.count >= 10n) throw new Error('Escrow approval rate limited');
      const rows = await tx.$executeRawUnsafe(
        'INSERT INTO "escrow_authorization" ("nonce", "policyHash", "dryRun", "operatorId", "approverId") VALUES ($1, $2, $3, $4, $5)',
        request.nonce, request.policyHash, request.dryRun, request.operatorId, request.approverId,
      );
      if (rows !== 1) throw new Error('Escrow nonce not consumed');
      return true as const;
    }, { isolationLevel: 'ReadCommitted', maxWait: 10_000, timeout: 15_000 }),
  };
}
