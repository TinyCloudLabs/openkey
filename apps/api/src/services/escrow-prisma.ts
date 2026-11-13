import type { PrismaClient } from '@openkey/db';
import type { EscrowSqlDatabase } from './escrow-snapshot';

/** Adapts an explicitly supplied Prisma client without any pre-LOCK query. */
export function createPrismaEscrowDatabase(prisma: Pick<PrismaClient, '$transaction'>): EscrowSqlDatabase {
  return {
    $transaction: (operation, options) => prisma.$transaction(tx => operation({
      $executeRawUnsafe: (query, ...values) => tx.$executeRawUnsafe(query, ...values),
      $queryRawUnsafe: <T>(query: string, ...values: unknown[]) => tx.$queryRawUnsafe<T>(query, ...values),
    }), options),
  };
}
