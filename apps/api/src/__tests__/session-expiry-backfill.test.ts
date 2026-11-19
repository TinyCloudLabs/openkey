// scripts/ci-backfill-session-expiry.ts on a real (PGlite) database with the tracked migrations:
// the function with an injected SQL client, and the script itself through Prisma.

import './tc1777-test-env';
import { afterAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = resolve(import.meta.dir, '../../../..');
const script = join(root, 'scripts/ci-backfill-session-expiry.ts');

// The script lives outside this project's source root, so it is loaded by path and described here.
interface SqlTransaction {
  rows<T = Record<string, unknown>>(sql: string): Promise<T[]>;
  execute(sql: string): Promise<number>;
}
interface SqlClient {
  transaction<T>(run: (transaction: SqlTransaction) => Promise<T>): Promise<T>;
}
interface BackfillModule {
  BACKUP_TABLE: string;
  BackfillRefused: new (message: string) => Error;
  BackfillMismatch: new (capped: number, backedUp: number) => Error;
  SQL: { backupExists: string; createBackup: string; cap: string };
  parseMode(value: string | undefined): 'apply' | 'rollback';
  describeFailure(error: unknown): { exitCode: number; line: string };
  runBackfill(client: SqlClient, mode: 'apply' | 'rollback', log: (line: string) => void): Promise<Record<string, unknown>>;
}
const { BACKUP_TABLE, BackfillRefused, BackfillMismatch, SQL, parseMode, describeFailure, runBackfill } = (await import(pathToFileURL(script).href)) as BackfillModule;

const migrationSql = (async () => {
  const names = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  return Promise.all(names.map((name) => readFile(join(root, 'packages/db/prisma/migrations', name, 'migration.sql'), 'utf8')));
})();

/** `age` days before the fixed moment `2026-10-26 00:00:00`, with an expiry `expiresAfter` days after creation. */
interface Seed { id: string; age: number; expiresAfter: number }
const SESSIONS: Seed[] = [
  { id: 'young-2d', age: 2, expiresAfter: 7 },
  { id: 'old-29d-over', age: 29, expiresAfter: 36 },
  { id: 'old-35d-over', age: 35, expiresAfter: 42 },
  { id: 'old-40d-over', age: 40, expiresAfter: 47 },
  { id: 'old-29d-at-cap', age: 29, expiresAfter: 30 },
  { id: 'young-10d', age: 10, expiresAfter: 7 },
  { id: 'old-35d-expired', age: 35, expiresAfter: 7 },
];
const OVER_CAP = ['old-29d-over', 'old-35d-over', 'old-40d-over'];

const timestamp = (age: number, plusDays = 0) => {
  const at = Date.UTC(2026, 9, 26) - age * 86_400_000 + plusDays * 86_400_000;
  return new Date(at).toISOString().replace('T', ' ').replace('Z', '');
};
/** Milliseconds from a Postgres `timestamp` text such as `2026-09-30 00:00:00` (all times here are UTC). */
const ms = (text: string) => Date.parse(`${text.replace(' ', 'T')}Z`);

async function seedRows(db: PGlite, rows: Seed[] = SESSIONS) {
  await db.exec(`INSERT INTO "user" (id, email, "updatedAt") VALUES ('u1', 'u1@example.test', '2026-10-26 00:00:00') ON CONFLICT DO NOTHING`);
  for (const row of rows) {
    await db.query(
      `INSERT INTO "session" (id, "userId", token, "expiresAt", "createdAt", "updatedAt") VALUES ($1, 'u1', $2, $3, $4, $4)`,
      [row.id, `token-${row.id}`, timestamp(row.age, row.expiresAfter), timestamp(row.age)],
    );
  }
}

async function freshDatabase(rows?: Seed[]): Promise<PGlite> {
  const db = new PGlite();
  for (const sql of await migrationSql) await db.exec(sql);
  await seedRows(db, rows);
  return db;
}

type Snapshot = Record<string, string>;
async function snapshot(db: PGlite): Promise<Snapshot> {
  const { rows } = await db.query<{ id: string; expiresAt: string }>(`SELECT id, "expiresAt"::text AS "expiresAt" FROM "session" ORDER BY id`);
  return Object.fromEntries(rows.map((row) => [row.id, row.expiresAt]));
}

async function backupTable(db: PGlite): Promise<Snapshot | null> {
  const present = await db.query<{ present: boolean }>(SQL.backupExists);
  if (!present.rows[0]!.present) return null;
  const { rows } = await db.query<{ id: string; expiresAt: string }>(`SELECT id, "expiresAt"::text AS "expiresAt" FROM ${BACKUP_TABLE} ORDER BY id`);
  return Object.fromEntries(rows.map((row) => [row.id, row.expiresAt]));
}

/** Whether the schema that holds the backup exists, and how many backup-like tables the application schema has. */
async function schemaState(db: PGlite): Promise<{ backupSchema: boolean; applicationTables: number }> {
  const schema = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM information_schema.schemata WHERE schema_name = 'ops_backup'`);
  const tables = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema = 'public' AND table_name LIKE 'session_expires%'`);
  return { backupSchema: schema.rows[0]!.n === 1, applicationTables: tables.rows[0]!.n };
}

/** A SQL client over PGlite; `wrap` can alter what a transaction returns, to inject a fault. */
function clientFor(db: PGlite, wrap: (transaction: SqlTransaction) => SqlTransaction = (transaction) => transaction): SqlClient {
  return {
    transaction: (run) => db.transaction((pg) => run(wrap({
      rows: async <T>(sql: string) => (await pg.query(sql)).rows as T[],
      execute: async (sql: string) => (await pg.query(sql)).affectedRows ?? 0,
    }))),
  };
}

const lines = () => {
  const printed: string[] = [];
  return { printed, log: (line: string) => printed.push(line) };
};

describe('apply', () => {
  test('backs up and caps exactly the sessions more than 30 days past their creation, and nothing else', async () => {
    const db = await freshDatabase();
    const before = await snapshot(db);
    const { printed, log } = lines();

    const result = await runBackfill(clientFor(db), 'apply', log);

    expect(result).toEqual({ mode: 'apply', backedUp: 3, capped: 3 });
    expect(printed).toEqual(['backed up: 3', 'capped: 3']);
    const backup = await backupTable(db);
    expect(Object.keys(backup!)).toEqual(OVER_CAP);
    for (const id of OVER_CAP) expect(backup![id]).toBe(before[id]!);

    const after = await snapshot(db);
    for (const seed of SESSIONS) {
      const expected = OVER_CAP.includes(seed.id) ? timestamp(seed.age, 30) : before[seed.id]!;
      expect(ms(after[seed.id]!), seed.id).toBe(ms(expected));
    }
  }, 60_000);

  test('never extends a session: no expiry is later afterwards', async () => {
    const db = await freshDatabase();
    const before = await snapshot(db);
    await runBackfill(clientFor(db), 'apply', () => {});
    const after = await snapshot(db);
    for (const id of Object.keys(before)) expect(ms(after[id]!), id).toBeLessThanOrEqual(ms(before[id]!));
  }, 60_000);

  test('with no session over the cap it backs up nothing and changes nothing', async () => {
    const db = await freshDatabase(SESSIONS.filter((seed) => !OVER_CAP.includes(seed.id)));
    const before = await snapshot(db);
    const { printed, log } = lines();
    expect(await runBackfill(clientFor(db), 'apply', log)).toEqual({ mode: 'apply', backedUp: 0, capped: 0 });
    expect(printed).toEqual(['backed up: 0', 'capped: 0']);
    expect(await snapshot(db)).toEqual(before);
    expect(await backupTable(db)).toEqual({});
  }, 60_000);

  test('a second apply is refused and changes nothing', async () => {
    const db = await freshDatabase();
    await runBackfill(clientFor(db), 'apply', () => {});
    const sessions = await snapshot(db);
    const backup = await backupTable(db);

    const { printed, log } = lines();
    await expect(runBackfill(clientFor(db), 'apply', log)).rejects.toBeInstanceOf(BackfillRefused);
    expect(printed).toEqual([]);
    expect(await snapshot(db)).toEqual(sessions);
    expect(await backupTable(db)).toEqual(backup);
  }, 60_000);

  test('a count mismatch rolls the whole transaction back: no backup table, no session changed', async () => {
    const db = await freshDatabase();
    const before = await snapshot(db);
    const faulty = clientFor(db, (transaction) => ({
      rows: transaction.rows,
      execute: async (sql) => (await transaction.execute(sql)) + (sql === SQL.cap ? 1 : 0),
    }));

    await expect(runBackfill(faulty, 'apply', () => {})).rejects.toBeInstanceOf(BackfillMismatch);
    expect(await backupTable(db)).toBeNull();
    expect(await snapshot(db)).toEqual(before);
  }, 60_000);

  test('after a rolled-back run, apply can be run again', async () => {
    const db = await freshDatabase();
    const faulty = clientFor(db, (transaction) => ({
      rows: transaction.rows,
      execute: async (sql) => (await transaction.execute(sql)) + (sql === SQL.cap ? 1 : 0),
    }));
    await expect(runBackfill(faulty, 'apply', () => {})).rejects.toThrow();
    expect(await runBackfill(clientFor(db), 'apply', () => {})).toEqual({ mode: 'apply', backedUp: 3, capped: 3 });
  }, 60_000);

  test('the backup is in its own schema: the application schema gets no table, and a rolled-back run leaves no schema', async () => {
    const db = await freshDatabase();
    expect(await schemaState(db)).toEqual({ backupSchema: false, applicationTables: 0 });
    await runBackfill(clientFor(db), 'apply', () => {});
    expect(await schemaState(db)).toEqual({ backupSchema: true, applicationTables: 0 });

    const other = await freshDatabase();
    const faulty = clientFor(other, (transaction) => ({
      rows: transaction.rows,
      execute: async (sql) => (await transaction.execute(sql)) + (sql === SQL.cap ? 1 : 0),
    }));
    await expect(runBackfill(faulty, 'apply', () => {})).rejects.toBeInstanceOf(BackfillMismatch);
    expect(await schemaState(other)).toEqual({ backupSchema: false, applicationTables: 0 });
  }, 60_000);

  test('a session pushed over the cap after the backup was taken is not in it, and is not capped', async () => {
    const db = await freshDatabase();
    const pushed = clientFor(db, (transaction) => ({
      rows: transaction.rows,
      execute: async (sql) => {
        const changed = await transaction.execute(sql);
        if (sql === SQL.createBackup) {
          await transaction.execute(`UPDATE "session" SET "expiresAt" = "createdAt" + interval '40 days' WHERE id = 'young-10d'`);
        }
        return changed;
      },
    }));
    const before = await snapshot(db);

    expect(await runBackfill(pushed, 'apply', () => {})).toEqual({ mode: 'apply', backedUp: 3, capped: 3 });
    expect(Object.keys((await backupTable(db))!)).toEqual(OVER_CAP);
    const after = await snapshot(db);
    // Only the backed-up sessions were capped: the pushed one keeps the expiry it was given.
    expect(ms(after['young-10d']!)).toBe(ms(timestamp(10, 40)));
    expect(ms(before['young-10d']!)).not.toBe(ms(after['young-10d']!));
  }, 60_000);

  test('a backed-up session that changed before the update makes the counts differ, and the run is rolled back', async () => {
    const db = await freshDatabase();
    const before = await snapshot(db);
    const changed = clientFor(db, (transaction) => ({
      rows: transaction.rows,
      execute: async (sql) => {
        const count = await transaction.execute(sql);
        if (sql === SQL.createBackup) {
          await transaction.execute(`UPDATE "session" SET "expiresAt" = "createdAt" + interval '5 days' WHERE id = 'old-35d-over'`);
        }
        return count;
      },
    }));

    await expect(runBackfill(changed, 'apply', () => {})).rejects.toBeInstanceOf(BackfillMismatch);
    expect(await backupTable(db)).toBeNull();
    expect(await schemaState(db)).toEqual({ backupSchema: false, applicationTables: 0 });
    expect(await snapshot(db)).toEqual(before);
  }, 60_000);
});

describe('rollback', () => {
  test('puts back the original expiry of every capped session, exactly, and leaves the backup table', async () => {
    const db = await freshDatabase();
    const original = await snapshot(db);
    await runBackfill(clientFor(db), 'apply', () => {});
    expect(await snapshot(db)).not.toEqual(original);
    const backup = await backupTable(db);

    const { printed, log } = lines();
    expect(await runBackfill(clientFor(db), 'rollback', log)).toEqual({ mode: 'rollback', restored: 3, leftAlone: 0 });
    expect(printed).toEqual(['restored: 3', 'left alone: 0']);
    expect(await snapshot(db)).toEqual(original);
    expect(await backupTable(db)).toEqual(backup);
  }, 60_000);

  test('is refused without a backup table, and changes nothing', async () => {
    const db = await freshDatabase();
    const before = await snapshot(db);
    const { printed, log } = lines();
    await expect(runBackfill(clientFor(db), 'rollback', log)).rejects.toBeInstanceOf(BackfillRefused);
    expect(printed).toEqual([]);
    expect(await snapshot(db)).toEqual(before);
    expect(await backupTable(db)).toBeNull();
  }, 60_000);

  test('restores only the sessions that are still there', async () => {
    const db = await freshDatabase();
    await runBackfill(clientFor(db), 'apply', () => {});
    await db.exec(`DELETE FROM "session" WHERE id = 'old-35d-over'`);
    expect(await runBackfill(clientFor(db), 'rollback', () => {})).toEqual({ mode: 'rollback', restored: 2, leftAlone: 1 });
    expect((await snapshot(db))['old-35d-over']).toBeUndefined();
  }, 60_000);

  test('a session whose expiry changed after apply is left alone: not lengthened and not revived', async () => {
    const db = await freshDatabase();
    await runBackfill(clientFor(db), 'apply', () => {});
    // One ended (its expiry is now earlier than the cap), one given another expiry (later than the cap).
    await db.exec(`UPDATE "session" SET "expiresAt" = '2026-10-26 00:00:00' WHERE id = 'old-35d-over'`);
    await db.exec(`UPDATE "session" SET "expiresAt" = "createdAt" + interval '33 days' WHERE id = 'old-40d-over'`);
    const before = await snapshot(db);

    const { printed, log } = lines();
    expect(await runBackfill(clientFor(db), 'rollback', log)).toEqual({ mode: 'rollback', restored: 1, leftAlone: 2 });
    expect(printed).toEqual(['restored: 1', 'left alone: 2']);
    const after = await snapshot(db);
    expect(after['old-35d-over']).toBe(before['old-35d-over']!);
    expect(after['old-40d-over']).toBe(before['old-40d-over']!);
    // The session that still held the capped value is the one that got its old expiry back.
    expect(ms(after['old-29d-over']!)).toBe(ms(timestamp(29, 36)));
  }, 60_000);
});

describe('what is printed', () => {
  test('counts only: no session ids, tokens or times', async () => {
    const db = await freshDatabase();
    const { printed, log } = lines();
    await runBackfill(clientFor(db), 'apply', log);
    await runBackfill(clientFor(db), 'rollback', log);
    expect(printed.length).toBe(4);
    for (const line of printed) expect(line).toMatch(/^(backed up|capped|restored|left alone): \d+$/);
  }, 60_000);

  test('the mode must be apply or rollback', () => {
    expect(parseMode('apply')).toBe('apply');
    expect(parseMode('rollback')).toBe('rollback');
    for (const value of [undefined, '', 'Apply', 'both', 'restore']) expect(() => parseMode(value)).toThrow(BackfillRefused);
  });
});

describe('a failure that is not one of ours', () => {
  test('a driver error that carries a host name prints only the fixed line', () => {
    const driver = new Error('connect ECONNREFUSED db.example.neon.tech:5432');
    expect(describeFailure(driver)).toEqual({ exitCode: 1, line: 'Error: the backfill failed and was rolled back' });
  });

  test('nor does a driver error whose text says "rolled back" print its text', () => {
    const driver = new Error('transaction rolled back: could not reach postgres://user:secret@db.example.neon.tech:5432/app');
    const { line } = describeFailure(driver);
    expect(line).toBe('Error: the backfill failed and was rolled back');
    expect(line).not.toContain('neon');
    expect(line).not.toContain('secret');
  });

  test('only our own errors print their message', () => {
    expect(describeFailure(new BackfillRefused('the backup table already exists'))).toEqual({ exitCode: 2, line: 'Refused: the backup table already exists' });
    expect(describeFailure(new BackfillMismatch(2, 3))).toEqual({
      exitCode: 1,
      line: 'Error: the capped count (2) differs from the backed-up count (3); rolled back',
    });
    expect(describeFailure('not even an error')).toEqual({ exitCode: 1, line: 'Error: the backfill failed and was rolled back' });
  });
});

describe('the script, through Prisma', () => {
  let directory: string | undefined;
  afterAll(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

  async function prepare() {
    if (directory) await rm(directory, { recursive: true, force: true });
    directory = await mkdtemp('/var/tmp/tc2101-backfill.');
    const db = new PGlite(directory);
    try {
      for (const sql of await migrationSql) await db.exec(sql);
      await seedRows(db);
    } finally {
      await db.close();
    }
  }

  async function run(args: string[], env: Record<string, string | undefined>) {
    const child = Bun.spawn([process.execPath, script, ...args], {
      cwd: root,
      env: { ...process.env, DATABASE_URL: `pglite:${directory}`, OPENKEY_DATABASE_SCHEMA: undefined, BACKFILL_CONFIRM: undefined, ...env } as unknown as Record<string, string>,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    return { stdout, stderr, exitCode };
  }

  async function stored(): Promise<{ sessions: Snapshot; backup: Snapshot | null }> {
    const db = new PGlite(directory);
    try {
      return { sessions: await snapshot(db), backup: await backupTable(db) };
    } finally {
      await db.close();
    }
  }

  test('apply, a second apply, and rollback, with their output and exit codes', async () => {
    await prepare();
    const original = (await stored()).sessions;

    const applied = await run(['--mode', 'apply'], { BACKFILL_CONFIRM: 'apply' });
    expect(applied.exitCode, applied.stderr).toBe(0);
    expect(applied.stdout.trim().split('\n')).toEqual(['backed up: 3', 'capped: 3', 'apply done']);
    expect(applied.stderr).toBe('');
    const afterApply = await stored();
    expect(Object.keys(afterApply.backup!)).toEqual(OVER_CAP);
    expect(afterApply.sessions).not.toEqual(original);

    const again = await run(['--mode', 'apply'], { BACKFILL_CONFIRM: 'apply' });
    expect(again.exitCode).toBe(2);
    expect(again.stderr).toContain(`Refused: ${BACKUP_TABLE} already exists`);
    expect((await stored()).sessions).toEqual(afterApply.sessions);

    const rolled = await run(['--mode', 'rollback'], { BACKFILL_CONFIRM: 'rollback' });
    expect(rolled.exitCode, rolled.stderr).toBe(0);
    expect(rolled.stdout.trim().split('\n')).toEqual(['restored: 3', 'left alone: 0', 'rollback done']);
    const afterRollback = await stored();
    expect(afterRollback.sessions).toEqual(original);
    expect(afterRollback.backup).toEqual(afterApply.backup);

    for (const output of [applied.stdout, again.stdout, rolled.stdout, applied.stderr, again.stderr, rolled.stderr]) {
      expect(output).not.toContain('old-');
      expect(output).not.toContain('token-');
      expect(output).not.toContain('pglite');
    }
  }, 180_000);

  test.each([
    ['no confirmation', ['--mode', 'apply'], {}],
    ['a confirmation for the other mode', ['--mode', 'apply'], { BACKFILL_CONFIRM: 'rollback' }],
    ['an unknown mode', ['--mode', 'both'], { BACKFILL_CONFIRM: 'both' }],
    ['no mode', [], { BACKFILL_CONFIRM: 'apply' }],
  ] as Array<[string, string[], Record<string, string>]>)('%s is refused and changes nothing', async (_name, args, env) => {
    await prepare();
    const original = await stored();
    const result = await run(args, env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('Refused');
    expect(await stored()).toEqual(original);
  }, 90_000);

  test('rollback with no backup is refused', async () => {
    await prepare();
    const result = await run(['--mode', 'rollback'], { BACKFILL_CONFIRM: 'rollback' });
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain(`Refused: ${BACKUP_TABLE} does not exist`);
  }, 90_000);

  test('a database that cannot be reached prints only the fixed line, never the address or the credentials', async () => {
    const result = await run(['--mode', 'apply'], { BACKFILL_CONFIRM: 'apply', DATABASE_URL: 'postgresql://backfill-user:backfill-secret@127.0.0.1:1/openkey' });
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe('Error: the backfill failed and was rolled back\n');
    expect(result.stdout).toBe('');
  }, 90_000);
});
