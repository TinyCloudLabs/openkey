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

/** Each fixture owns an entire database so public-qualified production SQL is unchanged. */
export async function createEscrowTestDatabase(suffix = '_escrow_test') {
  const { Client } = await import('pg');
  const local = escrowTestPostgres(), control = new Client(local);
  await control.connect();
  const name = 'tc_' + crypto.randomUUID().replaceAll('-', '') + suffix;
  await control.query(`CREATE DATABASE "${name}"`);
  return { local: { ...local, database: name }, async cleanup() {
    try { await control.query(`DROP DATABASE "${name}"`); } finally { await control.end(); }
  } };
}
