#!/usr/bin/env bun
/**
 * CI Drop Session Expiry Backup (TC-2110)
 *
 * Removes `ops_backup.session_expires_20261026`, the backup table that the TC-2101 session
 * expiry backfill (`scripts/ci-backfill-session-expiry.ts`, #364) left in place. The 30-day web
 * session cap stays, so the backup is no longer needed.
 *
 * In one transaction, and only if the table holds exactly one row:
 *   1. checks the table exists (if not: "already gone", nothing changed, exit 0) and holds exactly
 *      one row (any other count: refused, nothing changed);
 *   2. `DROP TABLE ops_backup.session_expires_20261026` (no CASCADE);
 *   3. `DROP SCHEMA ops_backup` (no CASCADE) only if nothing else is left in it.
 * Afterwards a separate read-only transaction confirms the table is gone and reports whether the
 * schema was dropped or kept.
 *
 * Env:
 *   DATABASE_URL   Postgres connection string (required)
 *   DROP_CONFIRM   Must equal `drop-ops_backup.session_expires_20261026` (required)
 *
 * Output: the row count, column names, and fixed text. No row values, no connection strings.
 */

export const BACKUP_SCHEMA = 'ops_backup';
export const BACKUP_NAME = 'session_expires_20261026';
export const BACKUP_TABLE = `${BACKUP_SCHEMA}.${BACKUP_NAME}`;
export const CONFIRM_PHRASE = `drop-${BACKUP_TABLE}`;
/** The row count the backfill left in the backup table; any other count is refused. */
export const EXPECTED_ROWS = 1;

export const SQL = {
  // Read-only checks. Names are literals of this file; nothing is interpolated from input.
  relkind: `SELECT c.relkind::text AS kind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '${BACKUP_SCHEMA}' AND c.relname = '${BACKUP_NAME}'`,
  columns: `SELECT column_name::text AS name FROM information_schema.columns WHERE table_schema = '${BACKUP_SCHEMA}' AND table_name = '${BACKUP_NAME}' ORDER BY ordinal_position`,
  count: `SELECT count(*)::int AS n FROM ${BACKUP_TABLE}`,
  // Relations, functions and types: what would keep the schema from being dropped.
  schemaObjects: `SELECT ((SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '${BACKUP_SCHEMA}') + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = '${BACKUP_SCHEMA}') + (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = '${BACKUP_SCHEMA}'))::int AS n`,
  schemaExists: `SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = '${BACKUP_SCHEMA}'`,
  // The only statements that change anything. Neither has CASCADE: a dependent object makes them fail.
  dropTable: `DROP TABLE ${BACKUP_TABLE}`,
  dropSchema: `DROP SCHEMA ${BACKUP_SCHEMA}`,
} as const;

/** What the script needs from a database: a transaction that rolls back when the callback throws. */
export interface SqlTransaction {
  rows<T = Record<string, unknown>>(sql: string): Promise<T[]>;
  execute(sql: string): Promise<number>;
}
export interface SqlClient {
  transaction<T>(run: (transaction: SqlTransaction) => Promise<T>): Promise<T>;
}

/** A refusal that changed nothing, as opposed to a failure. */
export class DropRefused extends Error {}

export interface DropResult {
  /** `gone`: the table did not exist, nothing was changed. */
  outcome: 'dropped' | 'gone';
  /** Present when the table was dropped. */
  schema?: 'dropped' | 'kept';
  /** Objects left in the schema, when it was kept. */
  schemaObjects?: number;
}

export async function dropBackup(client: SqlClient, log: (line: string) => void): Promise<DropResult> {
  const result = await client.transaction<DropResult>(async (transaction) => {
    const [found] = await transaction.rows<{ kind: string }>(SQL.relkind);
    if (!found) {
      log(`${BACKUP_TABLE} does not exist: already gone, nothing was changed`);
      return { outcome: 'gone' };
    }
    if (found.kind !== 'r') throw new DropRefused(`${BACKUP_TABLE} is not an ordinary table; nothing was changed`);

    const columns = await transaction.rows<{ name: string }>(SQL.columns);
    log(`columns: ${columns.map((column) => column.name).join(', ')}`);
    const [counted] = await transaction.rows<{ n: number }>(SQL.count);
    const rows = Number(counted?.n);
    log(`rows: ${rows}`);
    // Fail closed: anything but exactly the expected count, including an unreadable count, is refused.
    if (rows !== EXPECTED_ROWS) throw new DropRefused(`${BACKUP_TABLE} holds ${Number.isFinite(rows) ? rows : 'an unknown number of'} rows, not ${EXPECTED_ROWS}; nothing was changed`);

    await transaction.execute(SQL.dropTable);
    const [left] = await transaction.rows<{ n: number }>(SQL.schemaObjects);
    const remaining = Number(left?.n);
    if (remaining === 0) {
      await transaction.execute(SQL.dropSchema);
      return { outcome: 'dropped', schema: 'dropped' };
    }
    // Also reached when the count cannot be read: the schema is only dropped on a proven 0.
    return { outcome: 'dropped', schema: 'kept', schemaObjects: Number.isFinite(remaining) ? remaining : undefined };
  });

  if (result.outcome === 'gone') return result;

  // Read-only verification, after the commit.
  const verified = await client.transaction(async (transaction) => {
    const [still] = await transaction.rows<{ kind: string }>(SQL.relkind);
    const [schema] = await transaction.rows<{ n: number }>(SQL.schemaExists);
    return { tablePresent: still !== undefined, schemaPresent: Number(schema?.n) === 1 };
  });
  if (verified.tablePresent) throw new Error(`${BACKUP_TABLE} still exists after the drop`);
  log(`verified: ${BACKUP_TABLE} no longer exists`);
  if (result.schema === 'dropped') {
    if (verified.schemaPresent) throw new Error(`schema ${BACKUP_SCHEMA} still exists after the drop`);
    log(`schema ${BACKUP_SCHEMA}: dropped (it was empty)`);
  } else {
    log(`schema ${BACKUP_SCHEMA}: kept (${result.schemaObjects ?? 'an unknown number of'} other object(s) in it)`);
  }
  return result;
}

/**
 * The exit code and the one line printed for a failure. Only our own refusals print their
 * message (fixed text and counts); any other error, a database driver's included, can carry a
 * host name or connection details, so it prints a fixed line.
 */
export function describeFailure(error: unknown): { exitCode: number; line: string } {
  if (error instanceof DropRefused) return { exitCode: 2, line: `Refused: ${error.message}` };
  return { exitCode: 1, line: 'Error: the drop failed; nothing was changed unless the log above says verified' };
}

async function main() {
  if (process.env.DROP_CONFIRM !== CONFIRM_PHRASE) throw new DropRefused(`DROP_CONFIRM must be ${CONFIRM_PHRASE}`);
  if (!process.env.DATABASE_URL?.trim()) throw new DropRefused('DATABASE_URL is required');

  // Dynamic on purpose: the exported functions (and the tests) load without Prisma or a database, and a refusal above never loads it.
  const { createPrismaClient } = await import('../packages/db/src/index');
  const prisma = createPrismaClient();
  const client: SqlClient = {
    transaction: (run) => prisma.$transaction(
      (tx) => run({
        rows: <T>(sql: string) => tx.$queryRawUnsafe<T[]>(sql),
        execute: (sql: string) => tx.$executeRawUnsafe(sql),
      }),
      { timeout: 120_000 },
    ),
  };
  try {
    await dropBackup(client, (line) => console.log(line));
    console.log('done');
  } finally {
    await prisma.$disconnect();
  }
}

if (import.meta.main) {
  main().catch((error) => {
    const { exitCode, line } = describeFailure(error);
    console.error(line);
    process.exit(exitCode);
  });
}
