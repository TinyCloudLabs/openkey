// Prisma with Neon serverless driver
// Used for admin dashboard database access on Cloudflare Pages
import { Pool, neonConfig } from '@neondatabase/serverless';
import { PrismaClient } from '@prisma/client';
import { getPrismaClient } from '@prisma/adapter-neon';
import ws from 'ws';

// Configure Neon for serverless environments
neonConfig.webSocketConstructor = ws;

let prisma: PrismaClient;

function getPrisma() {
  if (!prisma) {
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) {
      throw new Error('DATABASE_URL environment variable is not set');
    }

    const pool = new Pool({ connectionString: databaseUrl });
    const adapter = getPrismaClient(pool);
    prisma = new PrismaClient({ adapter });
  }
  return prisma;
}

export const db = getPrisma();
