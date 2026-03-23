// Prisma database client for admin dashboard
// Uses @prisma/adapter-pg for all connections (required by Prisma 7)
import { PrismaClient } from '@openkey/db';
import { PrismaPg } from '@prisma/adapter-pg';
import { env } from '$env/dynamic/private';

let prisma: PrismaClient;

function getPrisma() {
  if (!prisma) {
    if (!env.DATABASE_URL) {
      throw new Error('DATABASE_URL environment variable is not set');
    }

    const adapter = new PrismaPg({ connectionString: env.DATABASE_URL });
    prisma = new PrismaClient({ adapter });
  }
  return prisma;
}

// Lazy proxy to avoid initialization at import time
// This allows SvelteKit's SSR analysis to import this module
// without actually connecting to the database
function createLazyProxy(): PrismaClient {
  let instance: PrismaClient | null = null;
  return new Proxy({} as PrismaClient, {
    get(_, prop) {
      if (!instance) instance = getPrisma();
      return (instance as any)[prop];
    }
  });
}

export const db = createLazyProxy();
