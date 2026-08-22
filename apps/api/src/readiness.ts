import type { Context } from 'hono';
import { checkRuntimeSchemaContract, createPrismaClient } from '@openkey/db';

export type ReadinessCheck = () => Promise<{ ready: boolean }>;

export async function checkApiReadiness() {
  const database = createPrismaClient();
  try {
    return await checkRuntimeSchemaContract(database);
  } finally {
    await database.$disconnect();
  }
}

export function readinessHandler(check: ReadinessCheck = checkApiReadiness) {
  return async (c: Context) => {
    const result = await check();
    if (!result.ready) {
      // Deliberately expose no migration name, checksum, database details, or
      // connection error on this unauthenticated public endpoint.
      return c.json({ status: 'not_ready' }, 503);
    }
    return c.json({ status: 'ok', tee: process.env.TEE_MODE || 'development' });
  };
}
