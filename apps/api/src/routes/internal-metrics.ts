import { timingSafeEqual } from 'crypto';
import { Hono } from 'hono';
import { createPrismaClient } from '@openkey/db';

const prisma = createPrismaClient();

export const internalMetricsRouter = new Hono();

function authorized(authHeader: string | undefined): boolean {
  const token = process.env.INTERNAL_METRICS_TOKEN;
  if (!token) return false;
  if (!authHeader?.startsWith('Bearer ')) return false;

  const provided = authHeader.slice(7);
  const expectedBytes = Buffer.from(token);
  const providedBytes = Buffer.from(provided);
  if (expectedBytes.length !== providedBytes.length) return false;
  return timingSafeEqual(expectedBytes, providedBytes);
}

internalMetricsRouter.get('/', async (c) => {
  if (!process.env.INTERNAL_METRICS_TOKEN) {
    return c.json({ error: 'Internal metrics are not configured' }, 503);
  }

  if (!authorized(c.req.header('Authorization'))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [totalAccounts, newAccounts24h, totalKeys, activeKeys, newKeys24h] = await Promise.all([
    prisma.user.count(),
    prisma.user.count({ where: { createdAt: { gte: since } } }),
    prisma.ethereumKey.count(),
    prisma.ethereumKey.count({ where: { archivedAt: null } }),
    prisma.ethereumKey.count({ where: { createdAt: { gte: since }, archivedAt: null } })
  ]);

  return c.json({
    generatedAt: new Date().toISOString(),
    accounts: {
      total: totalAccounts,
      new24h: newAccounts24h
    },
    keys: {
      total: totalKeys,
      active: activeKeys,
      new24h: newKeys24h
    }
  });
});
