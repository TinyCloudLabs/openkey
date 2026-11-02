// scripts/ci-drop-session-expiry-backup.ts (TC-2110) on a real (PGlite) database: the function with an
// injected SQL client, and the script's own refusals.

import './tc1777-test-env';
import { describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = resolve(import.meta.dir, '../../../..');
const script = join(root, 'scripts/ci-drop-session-expiry-backup.ts');

// The script lives outside this project's source root, so it is loaded by path and described here.
interface SqlTransaction {
  rows<T = Record<string, unknown>>(sql: string): Promise<T[]>;
  execute(sql: string): Promise<number>;
}
interface SqlClient {
  transaction<T>(run: (transaction: SqlTransaction) => Promise<T>): Promise<T>;
}
interface DropModule {
  BACKUP_TABLE: string;
  CONFIRM_PHRASE: string;
  SQL: { dropTable: string; dropSchema: string };
  DropRefused: new (message: string) => Error;
  describeFailure(error: unknown): { exitCode: number; line: string };
  dropBackup(client: SqlClient, log: (line: string) => void): Promise<{ outcome: string; schema?: string; schemaObjects?: number }>;
}
const { BACKUP_TABLE, CONFIRM_PHRASE, SQL, DropRefused, describeFailure, dropBackup } = (await import(pathToFileURL(script).href)) as DropModule;

/** A database shaped like production after the backfill: the backup table with `rows` rows (values are secrets-shaped on purpose). */
async function database(rows: number, extra: string[] = []): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(`CREATE SCHEMA ops_backup; CREATE TABLE ${BACKUP_TABLE} (id text, "expiresAt" timestamp)`);
  for (let i = 0; i < rows; i++) await db.query(`INSERT INTO ${BACKUP_TABLE} VALUES ($1, '2026-10-26 00:00:00')`, [`secret-session-${i}`]);
  for (const sql of extra) await db.exec(sql);
  return db;
}

function clientFor(db: PGlite): SqlClient {
  return {
    transaction: (run) => db.transaction((pg) => run({
      rows: async <T>(sql: string) => (await pg.query(sql)).rows as T[],
      execute: async (sql: string) => (await pg.query(sql)).affectedRows ?? 0,
    })),
  };
}

async function state(db: PGlite) {
  const relations = await db.query<{ name: string }>(`SELECT n.nspname || '.' || c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'ops_backup' ORDER BY 1`);
  const schema = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = 'ops_backup'`);
  return { relations: relations.rows.map((row) => row.name), schema: schema.rows[0]!.n === 1 };
}

const lines = () => {
  const printed: string[] = [];
  return { printed, log: (line: string) => printed.push(line) };
};

describe('dropBackup', () => {
  test('one row: drops the table and the then-empty schema, printing the count and column names only', async () => {
    const db = await database(1);
    const { printed, log } = lines();

    expect(await dropBackup(clientFor(db), log)).toEqual({ outcome: 'dropped', schema: 'dropped' });

    expect(await state(db)).toEqual({ relations: [], schema: false });
    expect(printed).toEqual([
      'columns: id, expiresAt',
      'rows: 1',
      `committed: ${BACKUP_TABLE} dropped`,
      `verified: ${BACKUP_TABLE} no longer exists`,
      'schema ops_backup: dropped (it was empty)',
    ]);
    expect(printed.join('\n')).not.toContain('secret-session');
  });

  test('another table in the schema: drops only the backup table and keeps the schema and the other table', async () => {
    const db = await database(1, [`CREATE TABLE ops_backup.other_backup (id int); INSERT INTO ops_backup.other_backup VALUES (7)`]);
    const { printed, log } = lines();

    const result = await dropBackup(clientFor(db), log);

    expect(result.outcome).toBe('dropped');
    expect(result.schema).toBe('kept');
    expect(await state(db)).toEqual({ relations: ['ops_backup.other_backup'], schema: true });
    expect((await db.query<{ id: number }>(`SELECT id FROM ops_backup.other_backup`)).rows).toEqual([{ id: 7 }]);
    expect(printed.at(-1)).toMatch(/^schema ops_backup: kept \(\d+ other object\(s\) in it\)$/);
  });

  test('a function in the schema keeps the schema too, without failing', async () => {
    const db = await database(1, [`CREATE FUNCTION ops_backup.f() RETURNS int LANGUAGE sql AS 'SELECT 1'`]);
    const result = await dropBackup(clientFor(db), () => {});
    expect(result).toEqual({ outcome: 'dropped', schema: 'kept', schemaObjects: 1 });
    expect((await state(db)).schema).toBe(true);
  });

  test.each([
    ['a collation', `CREATE COLLATION ops_backup.c FROM "C"`],
    ['a text search configuration', `CREATE TEXT SEARCH CONFIGURATION ops_backup.cfg (COPY = simple)`],
    ['extended statistics', `CREATE TABLE public.stat_source (a int, b int); CREATE STATISTICS ops_backup.st ON a, b FROM public.stat_source`],
  ])('%s in the schema keeps the schema and still drops the table, without a failure', async (_name, sql) => {
    const db = await database(1, [sql]);
    const result = await dropBackup(clientFor(db), () => {});
    expect(result.outcome).toBe('dropped');
    expect(result.schema).toBe('kept');
    expect((await state(db)).schema).toBe(true);
    expect((await state(db)).relations).not.toContain('ops_backup.session_expires_20261026');
  });

  test.each([0, 2, 3])('%i rows: refused, nothing changed', async (rows) => {
    const db = await database(rows);
    const { printed, log } = lines();

    await expect(dropBackup(clientFor(db), log)).rejects.toBeInstanceOf(DropRefused);

    expect(await state(db)).toEqual({ relations: ['ops_backup.session_expires_20261026'], schema: true });
    expect((await db.query(`SELECT 1 FROM ${BACKUP_TABLE}`)).rows.length).toBe(rows);
    expect(printed).toEqual(['columns: id, expiresAt', `rows: ${rows}`]);
  });

  test.each([[[]], [[{ n: null }]]])('a count that cannot be read (%j) is refused, nothing changed', async (unreadable) => {
    const db = await database(1);
    const unreadableCount: SqlClient = {
      transaction: (run) => clientFor(db).transaction((transaction) => run({
        rows: async <T>(sql: string) => (sql === SQL.count ? unreadable : await transaction.rows(sql)) as T[],
        execute: transaction.execute,
      })),
    };
    await expect(dropBackup(unreadableCount, () => {})).rejects.toBeInstanceOf(DropRefused);
    expect(await state(db)).toEqual({ relations: ['ops_backup.session_expires_20261026'], schema: true });
  });

  test('table missing: "already gone", exits normally, and an existing schema is left alone', async () => {
    const db = new PGlite();
    await db.exec(`CREATE SCHEMA ops_backup; CREATE TABLE ops_backup.other_backup (id int)`);
    const { printed, log } = lines();

    expect(await dropBackup(clientFor(db), log)).toEqual({ outcome: 'gone' });

    expect(printed).toEqual([`${BACKUP_TABLE} does not exist: already gone, nothing was changed`]);
    expect(await state(db)).toEqual({ relations: ['ops_backup.other_backup'], schema: true });
  });

  test('a view of that name is refused and left alone', async () => {
    const db = new PGlite();
    await db.exec(`CREATE SCHEMA ops_backup; CREATE VIEW ${BACKUP_TABLE} AS SELECT 1 AS id`);
    await expect(dropBackup(clientFor(db), () => {})).rejects.toBeInstanceOf(DropRefused);
    expect((await state(db)).relations).toEqual(['ops_backup.session_expires_20261026']);
  });

  test('a dependent object elsewhere makes the whole run fail with nothing dropped (no CASCADE), and other tables are untouched', async () => {
    const db = await database(1, [
      `CREATE TABLE public.session (id text); INSERT INTO public.session VALUES ('s1')`,
      `CREATE VIEW public.v AS SELECT * FROM ${BACKUP_TABLE}`,
    ]);
    await expect(dropBackup(clientFor(db), () => {})).rejects.toThrow();
    expect(await state(db)).toEqual({ relations: ['ops_backup.session_expires_20261026'], schema: true });
    expect((await db.query(`SELECT id FROM public.session`)).rows).toEqual([{ id: 's1' }]);
    expect((await db.query(`SELECT 1 FROM public.v`)).rows.length).toBe(1);
  });

  test('tables outside the schema are untouched by a successful run', async () => {
    const db = await database(1, [`CREATE TABLE public.session (id text); INSERT INTO public.session VALUES ('s1')`]);
    await dropBackup(clientFor(db), () => {});
    expect((await db.query(`SELECT id FROM public.session`)).rows).toEqual([{ id: 's1' }]);
  });

  test('a failing schema drop rolls the table drop back too', async () => {
    const db = await database(1);
    const failing: SqlClient = {
      transaction: (run) => clientFor(db).transaction((transaction) => run({
        rows: transaction.rows,
        execute: async (sql) => {
          if (sql === SQL.dropSchema) throw new Error('boom');
          return transaction.execute(sql);
        },
      })),
    };

    await expect(dropBackup(failing, () => {})).rejects.toThrow('boom');
    expect(await state(db)).toEqual({ relations: ['ops_backup.session_expires_20261026'], schema: true });
  });

  test('the statements that change anything are exactly the two drops, without CASCADE', async () => {
    const db = await database(1);
    const changing: string[] = [];
    const recording: SqlClient = {
      transaction: (run) => clientFor(db).transaction((transaction) => run({
        rows: transaction.rows,
        execute: (sql) => { changing.push(sql); return transaction.execute(sql); },
      })),
    };
    await dropBackup(recording, () => {});
    expect(changing).toEqual([`DROP TABLE ${BACKUP_TABLE}`, 'DROP SCHEMA ops_backup']);
  });
});

describe('what is printed on failure', () => {
  test('a driver error carrying a connection string prints only the fixed line', () => {
    const { exitCode, line } = describeFailure(new Error('could not reach postgres://user:secret@db.example.neon.tech:5432/app'));
    expect(exitCode).toBe(1);
    expect(line).not.toContain('secret');
    expect(line).not.toContain('neon');
  });

  test('our refusals print their message with exit code 2', () => {
    expect(describeFailure(new DropRefused('holds 2 rows'))).toEqual({ exitCode: 2, line: 'Refused: holds 2 rows' });
  });
});

describe('the script', () => {
  async function run(env: Record<string, string | undefined>) {
    const child = Bun.spawn([process.execPath, script], {
      cwd: root,
      env: { ...process.env, DATABASE_URL: 'postgresql://drop-user:drop-secret@127.0.0.1:1/openkey', DROP_CONFIRM: undefined, ...env } as unknown as Record<string, string>,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    return { stdout, stderr, exitCode };
  }

  test.each([
    ['no confirmation', {}],
    ['the table name alone', { DROP_CONFIRM: BACKUP_TABLE }],
    ['the phrase with a suffix', { DROP_CONFIRM: `${CONFIRM_PHRASE} ` }],
    ['no database url', { DROP_CONFIRM: CONFIRM_PHRASE, DATABASE_URL: '' }],
  ] as Array<[string, Record<string, string>]>)('%s is refused before any connection', async (_name, env) => {
    const result = await run(env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('Refused');
    expect(result.stdout).toBe('');
    expect(result.stderr).not.toContain('drop-secret');
  }, 60_000);

  test('a database that cannot be reached prints only the fixed line, never the address or the credentials', async () => {
    const result = await run({ DROP_CONFIRM: CONFIRM_PHRASE });
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe(`${describeFailure(new Error()).line}\n`);
    expect(result.stdout).toBe('');
  }, 90_000);
});
