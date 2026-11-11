import type { PrismaClient } from '@openkey/db';
import type { EscrowSqlTransaction } from './escrow-snapshot';
import type { EscrowAuthorizationRecord, EscrowAuthorizationStore } from './escrow-approval';

/** Utility locks precede the first query/snapshot, including inside RR ceremonies. */
export async function lockEscrowAuthorization(tx: EscrowSqlTransaction): Promise<void> {
  await tx.$executeRawUnsafe('LOCK TABLE public."escrow_authorization", public."escrow_preflight" IN EXCLUSIVE MODE');
  await tx.$executeRawUnsafe('SET LOCAL search_path = pg_catalog, public');
}

export async function consumeEscrowAuthorization(tx: EscrowSqlTransaction, request: EscrowAuthorizationRecord): Promise<true> {
      const validity = await tx.$queryRawUnsafe<{ valid: boolean }[]>('SELECT pg_catalog.clock_timestamp() < $1::pg_catalog.timestamptz AS valid', request.expiresAt);
      if (validity.length !== 1 || validity[0]!.valid !== true) throw new Error('Escrow approval expired');
      const recent = await tx.$queryRawUnsafe<{ count: bigint }[]>('SELECT pg_catalog.count(*) AS count FROM public."escrow_authorization" WHERE "kind" = $1 AND "createdAt" > CURRENT_TIMESTAMP - INTERVAL \'1 hour\'', request.kind);
      if (recent.length !== 1 || recent[0]!.count >= (request.kind === 'preflight' ? 6n : 4n)) throw new Error('Escrow approval rate limited');
      if (request.kind === 'export') {
        const claimed = await tx.$executeRawUnsafe(
          'UPDATE public."escrow_preflight" SET "consumedAt" = pg_catalog.clock_timestamp(), "payload" = NULL WHERE "policyHash" = $1 AND "nonce" = $2 AND "consumedAt" IS NULL AND "expiresAt" > pg_catalog.clock_timestamp() AND "payload" IS NOT NULL',
          request.policyHash, request.nonce,
        );
        if (claimed !== 1) throw new Error('Preflight unavailable');
      }
      const rows = await tx.$executeRawUnsafe(
        'INSERT INTO public."escrow_authorization" ("nonce", "policyHash", "dryRun", "operatorId", "approverId", "kind") VALUES ($1, $2, $3, $4, $5, $6)',
        request.nonce, request.policyHash, request.dryRun, request.operatorId, request.approverId, request.kind,
      );
      if (rows !== 1) throw new Error('Escrow nonce not consumed');
      return true as const;
}

/** Standalone callers share the same lock order; ceremonies call consume inside their fence. */
export function createEscrowAuthorizationStore(prisma: Pick<PrismaClient, '$transaction'>): EscrowAuthorizationStore {
  return {
    consume: request => prisma.$transaction(async tx => {
      await lockEscrowAuthorization(tx);
      return consumeEscrowAuthorization(tx, request);
    }, { isolationLevel: 'ReadCommitted', maxWait: 10_000, timeout: 15_000 }),
  };
}
