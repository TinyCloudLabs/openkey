// OpenKey DB - Prisma client export
import { PrismaClient } from './generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';

export function createPrismaClient(opts?: { connectionString?: string; log?: Array<'query' | 'info' | 'warn' | 'error'> }) {
  const connStr = opts?.connectionString ?? process.env.DATABASE_URL;
  if (!connStr) {
    throw new Error('DATABASE_URL environment variable is not set');
  }
  const adapter = new PrismaPg({ connectionString: connStr });
  return new PrismaClient({ adapter, log: opts?.log });
}

// Lazy singleton - only connects when first accessed
let _prisma: PrismaClient | undefined;
export function getPrisma() {
  if (!_prisma) {
    _prisma = createPrismaClient();
  }
  return _prisma;
}

export { PrismaClient };
export * from './generated/prisma/client';
