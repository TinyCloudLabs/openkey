// Prisma database client for admin dashboard
// Uses Neon serverless adapter in production (Cloudflare Pages),
// direct PrismaClient in development
import { PrismaClient } from '@prisma/client';
import { env } from '$env/dynamic/private';
import { dev } from '$app/environment';
import { neon } from '@neondatabase/serverless';
import { PrismaNeon } from '@prisma/adapter-neon';

let prisma: PrismaClient;

function getPrisma() {
  if (!prisma) {
    if (!env.DATABASE_URL) {
      throw new Error('DATABASE_URL environment variable is not set');
    }

    if (dev) {
      // Development: direct connection (no adapter needed)
      prisma = new PrismaClient({
        datasourceUrl: env.DATABASE_URL,
      });
    } else {
      // Production (Cloudflare Pages): use Neon serverless adapter
      const sql = neon(env.DATABASE_URL);
      const adapter = new PrismaNeon(sql);
      prisma = new PrismaClient({ adapter });
    }
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
