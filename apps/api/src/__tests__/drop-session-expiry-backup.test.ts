// scripts/ci-drop-session-expiry-backup.ts (TC-2110) on a real (PGlite) database: the function with an
// injected SQL client, and the script's own refusals.

import './tc1777-test-env';
import { describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
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
  SQL: { count: string; lock: string; rowJson: string; dropTable: string; dropSchema: string };
  DropRefused: new (message: string) => Error;
  describeFailure(error: unknown): { exitCode: number; line: string };
  dropBackup(client: SqlClient, log: (line: string) => void, options?: { expectedDigest?: string }): Promise<{ outcome: string; schema?: string; schemaObjects?: number }>;
  backupRow(client: SqlClient, log: (line: string) => void): Promise<{ present: false } | { present: true; row: string; digest: string }>;
}
const { BACKUP_TABLE, CONFIRM_PHRASE, SQL, DropRefused, describeFailure, dropBackup, backupRow } = (await import(pathToFileURL(script).href)) as DropModule;

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

  test('the statements executed are the table lock and the two drops, without CASCADE', async () => {
    const db = await database(1);
    const executed: string[] = [];
    const recording: SqlClient = {
      transaction: (run) => clientFor(db).transaction((transaction) => run({
        rows: transaction.rows,
        execute: (sql) => { executed.push(sql); return transaction.execute(sql); },
      })),
    };
    await dropBackup(recording, () => {});
    expect(executed).toEqual([`LOCK TABLE ${BACKUP_TABLE} IN ACCESS EXCLUSIVE MODE`, `DROP TABLE ${BACKUP_TABLE}`, 'DROP SCHEMA ops_backup']);
  });

  test('the table is locked before the row count and the row are read, so nothing can change between the checks and the drop', async () => {
    const db = await database(1);
    const backup = await backupRow(clientFor(db), () => {});
    if (!backup.present) throw new Error('unreachable');
    const order: string[] = [];
    const recording: SqlClient = {
      transaction: (run) => clientFor(db).transaction((transaction) => run({
        rows: (sql) => { order.push(sql === SQL.count ? 'count' : sql === SQL.rowJson ? 'row' : 'other-read'); return transaction.rows(sql); },
        execute: (sql) => { order.push(sql === SQL.lock ? 'lock' : 'other-execute'); return transaction.execute(sql); },
      })),
    };
    await dropBackup(recording, () => {}, { expectedDigest: backup.digest });
    expect(order.indexOf('lock')).toBeGreaterThanOrEqual(0);
    expect(order.indexOf('lock')).toBeLessThan(order.indexOf('count'));
    expect(order.indexOf('lock')).toBeLessThan(order.indexOf('row'));
  });

  test('a missing table is reported without trying to lock it', async () => {
    const db = new PGlite();
    const executed: string[] = [];
    const recording: SqlClient = {
      transaction: (run) => clientFor(db).transaction((transaction) => run({
        rows: transaction.rows,
        execute: (sql) => { executed.push(sql); return transaction.execute(sql); },
      })),
    };
    expect(await dropBackup(recording, () => {})).toEqual({ outcome: 'gone' });
    expect(executed).toEqual([]);
  });
});

describe('backup before the drop', () => {
  test('backupRow returns the one row and its digest, changes nothing, and logs no row value', async () => {
    const db = await database(1);
    const before = await state(db);
    const { printed, log } = lines();

    const backup = await backupRow(clientFor(db), log);

    expect(backup.present).toBe(true);
    if (!backup.present) throw new Error('unreachable');
    expect(JSON.parse(backup.row)).toEqual({ id: 'secret-session-0', expiresAt: '2026-10-26T00:00:00' });
    expect(backup.digest).toBe(createHash('sha256').update(backup.row).digest('hex'));
    expect(await state(db)).toEqual(before);
    expect((await db.query(`SELECT 1 FROM ${BACKUP_TABLE}`)).rows.length).toBe(1);
    expect(printed.join('\n')).not.toContain('secret-session');
  });

  test.each([0, 2])('backupRow with %i rows is refused and changes nothing', async (rows) => {
    const db = await database(rows);
    await expect(backupRow(clientFor(db), () => {})).rejects.toBeInstanceOf(DropRefused);
    expect((await db.query(`SELECT 1 FROM ${BACKUP_TABLE}`)).rows.length).toBe(rows);
  });

  test('backupRow on a missing table reports "already gone" and creates nothing', async () => {
    const db = new PGlite();
    const { printed, log } = lines();
    expect(await backupRow(clientFor(db), log)).toEqual({ present: false });
    expect(printed).toEqual([`${BACKUP_TABLE} does not exist: already gone, nothing to back up`]);
  });

  test('backupRow only reads: it executes nothing and every query is a SELECT, so a backup-only run cannot drop', async () => {
    const db = await database(1);
    const executed: string[] = [];
    const reads: string[] = [];
    const recording: SqlClient = {
      transaction: (run) => clientFor(db).transaction((transaction) => run({
        rows: (sql) => { reads.push(sql); return transaction.rows(sql); },
        execute: (sql) => { executed.push(sql); return transaction.execute(sql); },
      })),
    };
    expect((await backupRow(recording, () => {})).present).toBe(true);
    expect(executed).toEqual([]);
    for (const sql of reads) expect(sql).toMatch(/^SELECT /);
    expect(await state(db)).toEqual({ relations: ['ops_backup.session_expires_20261026'], schema: true });
  });

  test('the drop goes ahead when the row still hashes to the backed-up one', async () => {
    const db = await database(1);
    const backup = await backupRow(clientFor(db), () => {});
    if (!backup.present) throw new Error('unreachable');
    const { printed, log } = lines();

    expect(await dropBackup(clientFor(db), log, { expectedDigest: backup.digest })).toEqual({ outcome: 'dropped', schema: 'dropped' });

    expect(await state(db)).toEqual({ relations: [], schema: false });
    expect(printed).toContain('row matches the backup taken in this run');
  });

  test('the row changed after the backup: refused, nothing dropped', async () => {
    const db = await database(1);
    const backup = await backupRow(clientFor(db), () => {});
    if (!backup.present) throw new Error('unreachable');
    await db.exec(`UPDATE ${BACKUP_TABLE} SET "expiresAt" = '2026-11-01 00:00:00'`);

    await expect(dropBackup(clientFor(db), () => {}, { expectedDigest: backup.digest })).rejects.toBeInstanceOf(DropRefused);

    expect(await state(db)).toEqual({ relations: ['ops_backup.session_expires_20261026'], schema: true });
  });

  test('the row was replaced by another single row after the backup: refused, nothing dropped', async () => {
    const db = await database(1);
    const backup = await backupRow(clientFor(db), () => {});
    if (!backup.present) throw new Error('unreachable');
    await db.exec(`DELETE FROM ${BACKUP_TABLE}`);
    await db.query(`INSERT INTO ${BACKUP_TABLE} VALUES ($1, '2026-10-26 00:00:00')`, ['another-session']);

    await expect(dropBackup(clientFor(db), () => {}, { expectedDigest: backup.digest })).rejects.toBeInstanceOf(DropRefused);

    expect((await db.query(`SELECT id FROM ${BACKUP_TABLE}`)).rows).toEqual([{ id: 'another-session' }]);
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
  const DIGEST = '0'.repeat(64);
  async function run(env: Record<string, string | undefined>, ...args: string[]) {
    const child = Bun.spawn([process.execPath, script, ...args], {
      cwd: root,
      env: {
        ...process.env,
        DATABASE_URL: 'postgresql://drop-user:drop-secret@127.0.0.1:1/openkey',
        DROP_CONFIRM: undefined,
        BACKUP_FILE: undefined,
        BACKUP_DIGEST: DIGEST,
        EXPECTED_SHA256: DIGEST,
        ...env,
      } as unknown as Record<string, string>,
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
    const result = await run(env, 'drop');
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('Refused');
    expect(result.stdout).toBe('');
    expect(result.stderr).not.toContain('drop-secret');
  }, 60_000);

  test.each([
    ['no mode', [], { DROP_CONFIRM: CONFIRM_PHRASE, BACKUP_FILE: '/nonexistent/backup.json' }],
    ['an unknown mode', ['rollback'], { DROP_CONFIRM: CONFIRM_PHRASE, BACKUP_FILE: '/nonexistent/backup.json' }],
    ['drop without the backup digest', ['drop'], { DROP_CONFIRM: CONFIRM_PHRASE, BACKUP_DIGEST: '' }],
    ['drop with a malformed digest', ['drop'], { DROP_CONFIRM: CONFIRM_PHRASE, BACKUP_DIGEST: 'abc' }],
    ['drop with an upper-case digest', ['drop'], { DROP_CONFIRM: CONFIRM_PHRASE, BACKUP_DIGEST: DIGEST.replace(/0/g, 'A') }],
    ['backup without a file path', ['backup'], { DROP_CONFIRM: CONFIRM_PHRASE }],
    ['drop without EXPECTED_SHA256', ['drop'], { DROP_CONFIRM: CONFIRM_PHRASE, EXPECTED_SHA256: '' }],
    ['drop with a malformed EXPECTED_SHA256', ['drop'], { DROP_CONFIRM: CONFIRM_PHRASE, EXPECTED_SHA256: 'abc' }],
    ['drop with an upper-case EXPECTED_SHA256', ['drop'], { DROP_CONFIRM: CONFIRM_PHRASE, EXPECTED_SHA256: 'A'.repeat(64) }],
  ] as Array<[string, string[], Record<string, string>]>)('%s is refused before any connection', async (_name, args, env) => {
    const result = await run(env, ...args);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('Refused');
    expect(result.stdout).toBe('');
  }, 60_000);

  test('drop whose backup does not match EXPECTED_SHA256 is refused before any connection', async () => {
    const result = await run({ DROP_CONFIRM: CONFIRM_PHRASE, EXPECTED_SHA256: '1'.repeat(64) }, 'drop');
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toBe('Refused: the backup taken in this run does not match EXPECTED_SHA256; nothing was changed\n');
    expect(result.stdout).toBe('');
  }, 60_000);

  test.each([
    ['drop with EXPECTED_SHA256 equal to the backup digest', 'drop', { DROP_CONFIRM: CONFIRM_PHRASE }],
    ['backup without the drop confirmation', 'backup', { BACKUP_FILE: join(tmpdir(), `tc2110-unreachable-${process.pid}.json`) }],
  ] as Array<[string, string, Record<string, string>]>)('%s passes every input check; a database that cannot be reached prints only the fixed line, never the address or the credentials', async (_name, mode, env) => {
    const result = await run(env, mode);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe(`${describeFailure(new Error()).line}\n`);
    expect(result.stdout).toBe('');
  }, 90_000);
});

describe('the workflow', () => {
  interface Step { if?: string; run?: string; env?: Record<string, string> }
  const workflow = Bun.YAML.parse(readFileSync(join(root, '.github/workflows/drop-session-expiry-backup.yml'), 'utf8')) as {
    on: { workflow_dispatch: { inputs: Record<string, { default?: string; required?: boolean }> } };
    jobs: { drop: { steps: Step[] } };
  };

  test('a dispatch defaults to backup-only and needs no confirmation; only a drop dispatch runs the drop, with the operator digest', () => {
    const { inputs } = workflow.on.workflow_dispatch;
    expect(inputs.mode?.default).toBe('backup-only');
    expect(inputs.confirm?.required).toBe(false);
    const dropSteps = workflow.jobs.drop.steps.filter((step) => /ci-drop-session-expiry-backup\.ts drop\b/.test(step.run ?? ''));
    expect(dropSteps).toHaveLength(1);
    expect(dropSteps[0]!.if).toStartWith("inputs.mode == 'drop' && ");
    expect(dropSteps[0]!.env?.EXPECTED_SHA256).toBe('${{ inputs.expected_sha256 }}');
  });
});
