import type { PrismaClient } from '@openkey/db';
import type { EscrowSqlDatabase } from './escrow-snapshot';

/** Adapts an explicitly supplied Prisma client without any pre-LOCK query. */
export function createPrismaEscrowDatabase(prisma: Pick<PrismaClient, '$transaction'>): EscrowSqlDatabase {
  return {
    $transaction: (operation, options) => prisma.$transaction(tx => operation({
      $executeRawUnsafe: query => tx.$executeRawUnsafe(query),
      $queryRawUnsafe: <T>(query: string) => tx.$queryRawUnsafe<T>(query),
    }), options),
  };
}
