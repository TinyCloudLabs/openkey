#!/usr/bin/env bun
/**
 * CI Session Expiry Backfill (TC-2101)
 *
 * One-time step for the 30-day cap on web sessions (#362). The cap applies when
 * a session is refreshed; a session created before it that is older than 30 days
 * and still has expiry left keeps that expiry until then, and the MCP token
 * status check reads it. This sets every such session's `expiresAt` to
 * `createdAt + 30 days`, keeping the old values in a backup table so the change
 * can be undone. The backup lives in its own schema (`ops_backup`), so the
 * application schema stays as the migrations define it.
 *
 *   --mode apply      Refuses if the backup table exists. In one transaction: creates the
 *                     schema `ops_backup` if needed, creates `ops_backup.session_expires_20261026`
 *                     (id, "expiresAt") from the sessions whose expiry is more than 30 days after
 *                     creation, then sets the expiry to `createdAt + 30 days` on the sessions in
 *                     that backup that are still over the cap. The transaction is rolled back if
 *                     the capped count differs from the backed-up count.
 *   --mode rollback   Refuses if the backup table is missing. In one transaction: puts the
 *                     backed-up expiry back on the sessions that still have the capped value;
 *                     a session whose expiry changed since, or that is gone, is left alone.
 *                     The backup table and schema are left in place; remove them by hand when
 *                     they are not needed.
 *
 * Env:
 *   DATABASE_URL       Postgres connection string (required)
 *   BACKFILL_CONFIRM   Must equal the mode (required)
 *
 * Output is counts only: no session ids, tokens or connection strings. A session whose
 * expiry is already within 30 days of creation is never changed, so no expiry is extended.
 */

export const BACKUP_SCHEMA = 'ops_backup';
export const BACKUP_TABLE = `${BACKUP_SCHEMA}.session_expires_20261026`;

/** The sessions the backfill saves: expiry more than 30 days after creation. */
const OVER_CAP = `"expiresAt" > "createdAt" + interval '30 days'`;

export const SQL = {
  backupExists: `SELECT to_regclass('${BACKUP_TABLE}') IS NOT NULL AS present`,
  createSchema: `CREATE SCHEMA IF NOT EXISTS ${BACKUP_SCHEMA}`,
  createBackup: `CREATE TABLE ${BACKUP_TABLE} AS SELECT id, "expiresAt" FROM "session" WHERE ${OVER_CAP}`,
  countBackup: `SELECT count(*)::int AS n FROM ${BACKUP_TABLE}`,
  // Through the backup: a session that is not in it is never touched.
  cap: `UPDATE "session" s SET "expiresAt" = s."createdAt" + interval '30 days' FROM ${BACKUP_TABLE} b WHERE s.id = b.id AND s."expiresAt" > s."createdAt" + interval '30 days'`,
  // Only a session still holding the capped value gets its old expiry back.
  restore: `UPDATE "session" s SET "expiresAt" = b."expiresAt" FROM ${BACKUP_TABLE} b WHERE s.id = b.id AND s."expiresAt" = s."createdAt" + interval '30 days'`,
} as const;

/** What the backfill needs from a database: a transaction that rolls back when the callback throws. */
export interface SqlTransaction {
  rows<T = Record<string, unknown>>(sql: string): Promise<T[]>;
  /** Runs a statement and returns the number of rows it changed. */
  execute(sql: string): Promise<number>;
}
export interface SqlClient {
  transaction<T>(run: (transaction: SqlTransaction) => Promise<T>): Promise<T>;
}

export type BackfillMode = 'apply' | 'rollback';

/** A refusal that changed nothing, as opposed to a failure. */
export class BackfillRefused extends Error {}

/** The capped count differs from the backed-up count; thrown inside the transaction, which is rolled back. */
export class BackfillMismatch extends Error {
  constructor(readonly capped: number, readonly backedUp: number) {
    super(`the capped count (${capped}) differs from the backed-up count (${backedUp}); rolled back`);
  }
}

export interface BackfillResult {
  mode: BackfillMode;
  /** Apply: sessions whose old expiry was saved, and then capped. */
  backedUp?: number;
  capped?: number;
  /** Rollback: sessions whose saved expiry was put back, and backed-up sessions left alone. */
  restored?: number;
  leftAlone?: number;
}

async function backupTableExists(transaction: SqlTransaction): Promise<boolean> {
  const [row] = await transaction.rows<{ present: boolean }>(SQL.backupExists);
  return row?.present === true;
}

export async function runBackfill(client: SqlClient, mode: BackfillMode, log: (line: string) => void): Promise<BackfillResult> {
  return client.transaction(async (transaction) => {
    const present = await backupTableExists(transaction);
    if (mode === 'apply') {
      if (present) throw new BackfillRefused(`${BACKUP_TABLE} already exists; nothing was changed`);
      await transaction.execute(SQL.createSchema);
      await transaction.execute(SQL.createBackup);
      const [counted] = await transaction.rows<{ n: number }>(SQL.countBackup);
      const backedUp = Number(counted?.n);
      log(`backed up: ${backedUp}`);
      const capped = await transaction.execute(SQL.cap);
      log(`capped: ${capped}`);
      // Thrown inside the transaction, so the backup table, the schema and the update are all undone.
      if (capped !== backedUp) throw new BackfillMismatch(capped, backedUp);
      return { mode, backedUp, capped };
    }
    if (!present) throw new BackfillRefused(`${BACKUP_TABLE} does not exist; nothing was changed`);
    const [counted] = await transaction.rows<{ n: number }>(SQL.countBackup);
    const restored = await transaction.execute(SQL.restore);
    const leftAlone = Number(counted?.n) - restored;
    log(`restored: ${restored}`);
    log(`left alone: ${leftAlone}`);
    return { mode, restored, leftAlone };
  });
}

export function parseMode(value: string | undefined): BackfillMode {
  if (value === 'apply' || value === 'rollback') return value;
  throw new BackfillRefused('--mode must be apply or rollback');
}

/**
 * The exit code and the one line printed for a failure. Only our own errors print their message
 * (counts and fixed text); any other error, a database driver's included, can carry a host name or
 * connection details, so it prints a fixed line.
 */
export function describeFailure(error: unknown): { exitCode: number; line: string } {
  if (error instanceof BackfillRefused) return { exitCode: 2, line: `Refused: ${error.message}` };
  if (error instanceof BackfillMismatch) return { exitCode: 1, line: `Error: ${error.message}` };
  return { exitCode: 1, line: 'Error: the backfill failed and was rolled back' };
}

async function main() {
  const { parseArgs } = await import('node:util');
  const { values } = parseArgs({ args: process.argv.slice(2), options: { mode: { type: 'string' } }, strict: true });
  const mode = parseMode(values.mode);
  if (process.env.BACKFILL_CONFIRM !== mode) throw new BackfillRefused(`BACKFILL_CONFIRM must be ${mode}`);
  if (!process.env.DATABASE_URL?.trim()) throw new BackfillRefused('DATABASE_URL is required');

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
    await runBackfill(client, mode, (line) => console.log(line));
    console.log(`${mode} done`);
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
