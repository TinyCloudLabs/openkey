import type { Context } from 'hono';
import { checkRuntimeSchemaContract, getPrisma, type SchemaContractDatabase } from '@openkey/db';
import { resolveTeeMode } from '@openkey/tee';

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
    // TEE_MODE selects a client, not the guest OS. Image identity and hardening
    // cannot be inferred without independently trusted runtime metadata.
    return c.json({ status: 'ok', tee_mode: resolveTeeMode(), os_image: 'unknown' });
  };
}
