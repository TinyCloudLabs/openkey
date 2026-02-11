// Prisma database client for admin dashboard
// Uses Neon serverless adapter in production (Cloudflare Pages),
// direct PrismaClient in development
import { PrismaClient } from '@prisma/client';
import { DATABASE_URL } from '$env/static/private';
import { dev } from '$app/environment';

let prisma: PrismaClient;

function getPrisma() {
  if (!prisma) {
    if (!DATABASE_URL) {
      throw new Error('DATABASE_URL environment variable is not set');
    }

    if (dev) {
      // Development: direct connection (no adapter needed)
      prisma = new PrismaClient({
        datasourceUrl: DATABASE_URL,
      });
    } else {
      // Production (Cloudflare Pages): use Neon serverless adapter
      // Dynamic import to avoid loading ws in production
      throw new Error('Production Neon adapter not yet configured - use db:push for now');
    }
  }
  return prisma;
}

export const db = getPrisma();
