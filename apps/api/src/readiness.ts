import type { Context } from 'hono';
import { checkRuntimeSchemaContract, getPrisma, type SchemaContractDatabase } from '@openkey/db';

export type ReadinessCheck = () => Promise<{ ready: boolean }>;

export async function checkApiReadiness(database: SchemaContractDatabase = getPrisma()) {
  return checkRuntimeSchemaContract(database);
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
