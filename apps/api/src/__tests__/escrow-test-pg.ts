import { isAbsolute } from 'node:path';
import { statSync } from 'node:fs';

/** Explicit disposable Unix socket only; never read DATABASE_URL or libpq defaults. */
export function escrowTestPostgres() {
  const host = process.env.OPENKEY_ESCROW_TEST_SOCKET;
  if (process.env.OPENKEY_ESCROW_TEST_PG !== '1' || !host || !isAbsolute(host) || host.includes('\0') || !statSync(host).isDirectory()) {
    throw new Error('Escrow PG tests require an explicit disposable Unix socket directory');
  }
  return { host, port: 55483, database: 'postgres', user: 'tinycloud' };
}
