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
 * Two modes (first argument):
 *   backup  read-only: checks the table exists and holds exactly one row, writes that row (JSON) to
 *           BACKUP_FILE, prints `backup-digest: <sha256 of the row text>`. The workflow encrypts and
 *           uploads it. Its `backup-only` dispatch runs this mode alone; a `drop` dispatch runs it first.
 *   drop    the steps above, and additionally refuses unless the backup taken in this run has the digest
 *           the operator verified from a backup-only run (EXPECTED_SHA256), and the row still hashes to it.
 *
 * Env:
 *   DATABASE_URL     Postgres connection string (required)
 *   DROP_CONFIRM     drop mode: must equal `drop-ops_backup.session_expires_20261026` (required)
 *   BACKUP_FILE      backup mode: path the row is written to, must not exist (required)
 *   BACKUP_DIGEST    drop mode: the digest printed by this run's backup step (required)
 *   EXPECTED_SHA256  drop mode: the digest from the backup-only run, verified against the decrypted
 *                    artifact (required, must equal BACKUP_DIGEST)
 *
 * Output: the row count, column names, and fixed text. No row values, no connection strings. The one
 * exception is `backup` mode, which writes the row to BACKUP_FILE (never to the log).
 */

import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

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
  // Normal dependencies on the schema: exactly what DROP SCHEMA (RESTRICT) refuses on. Relations, functions, types,
  // collations, text search objects, extended statistics and so on all have one. Run after the table drop, in its transaction.
  schemaObjects: `SELECT count(*)::int AS n FROM pg_depend WHERE refclassid = 'pg_namespace'::regclass AND refobjid = (SELECT oid FROM pg_namespace WHERE nspname = '${BACKUP_SCHEMA}') AND deptype = 'n'`,
  schemaExists: `SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = '${BACKUP_SCHEMA}'`,
  // The lock is taken first in the drop transaction (it changes no data); the two DROPs are the only statements that change
  // anything. Neither has CASCADE: a dependent object makes them fail.
  lock: `LOCK TABLE ${BACKUP_TABLE} IN ACCESS EXCLUSIVE MODE`,
  dropTable: `DROP TABLE ${BACKUP_TABLE}`,
  dropSchema: `DROP SCHEMA ${BACKUP_SCHEMA}`,
  // Read-only: the one row as JSON text, for the backup and for proving the drop sees the same row.
  rowJson: `SELECT row_to_json(t)::text AS row FROM ${BACKUP_TABLE} t`,
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

export type BackupResult = { present: false } | { present: true; row: string; digest: string };

export function rowDigest(row: string): string {
  return createHash('sha256').update(row).digest('hex');
}

export async function dropBackup(client: SqlClient, log: (line: string) => void, options: { expectedDigest?: string } = {}): Promise<DropResult> {
  const result = await client.transaction<DropResult>(async (transaction) => {
    const [found] = await transaction.rows<{ kind: string }>(SQL.relkind);
    if (!found) {
      log(`${BACKUP_TABLE} does not exist: already gone, nothing was changed`);
      return { outcome: 'gone' };
    }
    if (found.kind !== 'r') throw new DropRefused(`${BACKUP_TABLE} is not an ordinary table; nothing was changed`);
    // Held until the transaction ends: no write can land between the checks below and the drop.
    await transaction.execute(SQL.lock);

    const columns = await transaction.rows<{ name: string }>(SQL.columns);
    log(`columns: ${columns.map((column) => column.name).join(', ')}`);
    const [counted] = await transaction.rows<{ n: number }>(SQL.count);
    const rows = Number(counted?.n);
    log(`rows: ${rows}`);
    // Fail closed: anything but exactly the expected count, including an unreadable count, is refused.
    if (rows !== EXPECTED_ROWS) throw new DropRefused(`${BACKUP_TABLE} holds ${Number.isFinite(rows) ? rows : 'an unknown number of'} rows, not ${EXPECTED_ROWS}; nothing was changed`);
    // The row must be the one the backup step saved: refuse on any difference, before anything is dropped.
    if (options.expectedDigest !== undefined) {
      if (rowDigest(await readRow(transaction)) !== options.expectedDigest) {
        throw new DropRefused(`${BACKUP_TABLE} no longer matches the backup taken in this run; nothing was changed`);
      }
      log('row matches the backup taken in this run');
    }

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
  // Fixed text, so the log shows that the drop committed even if the verification below cannot run.
  log(`committed: ${BACKUP_TABLE} dropped`);

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
 * Reads the one row, read-only, for the backup step. The row text is what `row_to_json` returns and the
 * digest is its SHA-256, so the drop can prove it is dropping exactly the row that was backed up.
 * Same refusals as the drop: a table that is not an ordinary table, or any count but one, changes nothing.
 */
export async function backupRow(client: SqlClient, log: (line: string) => void): Promise<BackupResult> {
  return client.transaction<BackupResult>(async (transaction) => {
    const [found] = await transaction.rows<{ kind: string }>(SQL.relkind);
    if (!found) {
      log(`${BACKUP_TABLE} does not exist: already gone, nothing to back up`);
      return { present: false };
    }
    if (found.kind !== 'r') throw new DropRefused(`${BACKUP_TABLE} is not an ordinary table; nothing was changed`);
    const [counted] = await transaction.rows<{ n: number }>(SQL.count);
    const rows = Number(counted?.n);
    log(`rows: ${rows}`);
    if (rows !== EXPECTED_ROWS) throw new DropRefused(`${BACKUP_TABLE} holds ${Number.isFinite(rows) ? rows : 'an unknown number of'} rows, not ${EXPECTED_ROWS}; nothing was changed`);
    const row = await readRow(transaction);
    return { present: true, row, digest: rowDigest(row) };
  });
}

async function readRow(transaction: SqlTransaction): Promise<string> {
  const read = await transaction.rows<{ row: string }>(SQL.rowJson);
  if (read.length !== EXPECTED_ROWS || typeof read[0]?.row !== 'string') throw new DropRefused(`${BACKUP_TABLE} row could not be read; nothing was changed`);
  return read[0].row;
}

/**
 * The exit code and the one line printed for a failure. Only our own refusals print their
 * message (fixed text and counts); any other error, a database driver's included, can carry a
 * host name or connection details, so it prints a fixed line.
 */
export function describeFailure(error: unknown): { exitCode: number; line: string } {
  if (error instanceof DropRefused) return { exitCode: 2, line: `Refused: ${error.message}` };
  return { exitCode: 1, line: 'Error: the run failed; if the log above does not say committed, nothing was changed' };
}

async function main() {
  const mode = process.argv[2];
  if (mode !== 'backup' && mode !== 'drop') throw new DropRefused('the first argument must be backup or drop');
  if (mode === 'drop' && process.env.DROP_CONFIRM !== CONFIRM_PHRASE) throw new DropRefused(`DROP_CONFIRM must be ${CONFIRM_PHRASE}`);
  if (!process.env.DATABASE_URL?.trim()) throw new DropRefused('DATABASE_URL is required');
  const backupFile = process.env.BACKUP_FILE?.trim();
  const expectedDigest = process.env.BACKUP_DIGEST?.trim();
  const operatorDigest = process.env.EXPECTED_SHA256?.trim();
  if (mode === 'backup' && !backupFile) throw new DropRefused('BACKUP_FILE is required');
  if (mode === 'drop' && !(expectedDigest && DIGEST_PATTERN.test(expectedDigest))) {
    throw new DropRefused('BACKUP_DIGEST (the digest printed by the backup step) is required');
  }
  if (mode === 'drop' && !(operatorDigest && DIGEST_PATTERN.test(operatorDigest))) {
    throw new DropRefused('EXPECTED_SHA256 (the backup-digest of a backup-only run, 64 lowercase hex) is required');
  }
  if (mode === 'drop' && operatorDigest !== expectedDigest) {
    throw new DropRefused('the backup taken in this run does not match EXPECTED_SHA256; nothing was changed');
  }

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
    if (mode === 'backup') {
      const backup = await backupRow(client, (line) => console.log(line));
      if (backup.present) {
        // `wx`: never overwrite; 0600: the row is the only copy of the data, readable by this job only.
        writeFileSync(backupFile!, backup.row, { flag: 'wx', mode: 0o600 });
        console.log(`backup-digest: ${backup.digest}`);
      }
      console.log(`backup-present: ${backup.present}`);
    } else {
      await dropBackup(client, (line) => console.log(line), { expectedDigest });
    }
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
