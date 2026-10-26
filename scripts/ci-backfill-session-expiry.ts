#!/usr/bin/env bun
/**
 * CI Session Expiry Backfill (TC-2101)
 *
 * One-time step for the 30-day cap on web sessions (#362). The cap applies when
 * a session is refreshed; a session created before it that is older than 30 days
 * and still has expiry left keeps that expiry until then, and the MCP token
 * status check reads it. This sets every such session's `expiresAt` to
 * `createdAt + 30 days`, keeping the old values in a backup table so the change
 * can be undone.
 *
 *   --mode apply      Refuses if the backup table exists. In one transaction: creates
 *                     `session_expires_backup_20261026` (id, "expiresAt") from the sessions
 *                     whose expiry is more than 30 days after creation, then sets those
 *                     sessions' expiry to `createdAt + 30 days`. The transaction is rolled
 *                     back if the updated count differs from the backed-up count.
 *   --mode rollback   Refuses if the backup table is missing. In one transaction: puts the
 *                     backed-up expiry back on the sessions that are still there. The
 *                     backup table is left in place; remove it by hand when it is not needed.
 *
 * Env:
 *   DATABASE_URL       Postgres connection string (required)
 *   BACKFILL_CONFIRM   Must equal the mode (required)
 *
 * Output is counts only: no session ids, tokens or connection strings. A session whose
 * expiry is already within 30 days of creation is never changed, so no expiry is extended.
 */

export const BACKUP_TABLE = 'session_expires_backup_20261026';

/** The sessions the backfill touches: expiry more than 30 days after creation. */
const OVER_CAP = `"expiresAt" > "createdAt" + interval '30 days'`;

export const SQL = {
  backupExists: `SELECT to_regclass('${BACKUP_TABLE}') IS NOT NULL AS present`,
  createBackup: `CREATE TABLE ${BACKUP_TABLE} AS SELECT id, "expiresAt" FROM "session" WHERE ${OVER_CAP}`,
  countBackup: `SELECT count(*)::int AS n FROM ${BACKUP_TABLE}`,
  cap: `UPDATE "session" SET "expiresAt" = "createdAt" + interval '30 days' WHERE ${OVER_CAP}`,
  restore: `UPDATE "session" s SET "expiresAt" = b."expiresAt" FROM ${BACKUP_TABLE} b WHERE s.id = b.id`,
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

export interface BackfillResult {
  mode: BackfillMode;
  /** Apply: sessions whose old expiry was saved, and then capped. */
  backedUp?: number;
  capped?: number;
  /** Rollback: sessions whose saved expiry was put back. */
  restored?: number;
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
      await transaction.execute(SQL.createBackup);
      const [counted] = await transaction.rows<{ n: number }>(SQL.countBackup);
      const backedUp = Number(counted?.n);
      log(`backed up: ${backedUp}`);
      const capped = await transaction.execute(SQL.cap);
      log(`capped: ${capped}`);
      if (capped !== backedUp) {
        // Thrown inside the transaction, so the backup table and the update are both undone.
        throw new Error(`the capped count (${capped}) differs from the backed-up count (${backedUp}); rolled back`);
      }
      return { mode, backedUp, capped };
    }
    if (!present) throw new BackfillRefused(`${BACKUP_TABLE} does not exist; nothing was changed`);
    const restored = await transaction.execute(SQL.restore);
    log(`restored: ${restored}`);
    return { mode, restored };
  });
}

export function parseMode(value: string | undefined): BackfillMode {
  if (value === 'apply' || value === 'rollback') return value;
  throw new BackfillRefused('--mode must be apply or rollback');
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
    // Only our own messages are printed; a database error can carry connection details.
    if (error instanceof BackfillRefused) {
      console.error(`Refused: ${error.message}`);
      process.exit(2);
    }
    const ours = error instanceof Error && error.message.includes('rolled back');
    console.error(ours ? `Error: ${(error as Error).message}` : 'Error: the backfill failed and was rolled back');
    process.exit(1);
  });
}
