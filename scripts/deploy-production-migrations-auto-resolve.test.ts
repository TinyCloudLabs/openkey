import { afterAll, describe, expect, test } from 'bun:test';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from 'pg';
import {
  ABORTED_TRANSACTION_ERROR_LINE,
  MIGRATION_AUTO_RESOLVE_MIN_ELAPSED_MS,
  MIGRATION_DEPLOY_KILL_TIMEOUT_MS,
  MIGRATION_IDLE_IN_TRANSACTION_TIMEOUT_MS,
  MIGRATION_LOCK_TIMEOUT_MS,
  MIGRATION_STATEMENT_TIMEOUT_MS,
  decideAutoResolve,
  isOnlyAbortedTransactionError,
  listPresentMigrationObjects,
  migrateDeployWithAutoResolve,
  migrationChildEnv,
  reviewedMigrationObjects,
  runCapturedChild,
  withMigrationSessionLimits,
  type CapturedChild,
  type MigrationObjects,
  type MigrationRow,
  type QueryClient,
  type ReviewedMigration,
} from './deploy-production-migrations';

// What the schema engine printed (verified against Prisma 7.5.0 on Postgres 14 and 16) when a statement
// inside a migration's own BEGIN ... COMMIT failed on a lock timeout. The SQLSTATE never reaches the output.
const maskedFailure = [
  'Loaded Prisma config from prisma.config.ts.',
  '',
  'Prisma schema loaded from prisma/schema.prisma.',
  'Datasource "db": PostgreSQL database "openkey", schema "public" at "127.0.0.1:5432"',
  '',
  '65 migrations found in prisma/migrations',
  '',
  'Applying migration `20261021_0001_org_key_custody`',
  ABORTED_TRANSACTION_ERROR_LINE,
  '   0: schema_commands::commands::apply_migrations::Applying migration',
  '           with migration_name="20261021_0001_org_key_custody"',
  '             at schema-engine/commands/src/commands/apply_migrations.rs:95',
  '   1: schema_core::state::ApplyMigrations',
  '             at schema-engine/core/src/state.rs:255',
  '',
].join('\n');

const name = '20261021_0001_org_key_custody';
const noObjects: MigrationObjects = { types: [], columns: [], constraints: [], tables: [], indexes: [] };
const reviewed = new Map<string, ReviewedMigration>([[name, { checksum: 'reviewed', objects: noObjects }]]);
const unfinished: MigrationRow = { migration_name: name, checksum: 'reviewed', finished_at: null, rolled_back_at: null };
const baseChild: CapturedChild = { status: 1, output: maskedFailure, elapsedMs: 6000, timedOut: false };

function decide(overrides: {
  child?: Partial<CapturedChild>;
  rows?: MigrationRow[];
  reviewed?: ReadonlyMap<string, ReviewedMigration>;
  present?: string[];
}) {
  return decideAutoResolve({
    child: { ...baseChild, ...overrides.child },
    rows: overrides.rows ?? [unfinished],
    reviewed: overrides.reviewed ?? reviewed,
    presentObjects: async () => overrides.present ?? [],
  });
}

describe('the session limits of the migration connection', () => {
  const url = 'postgresql://deploy:s3cret%40pw@db.internal:5432/openkey';

  test('the named limits', () => {
    expect(MIGRATION_LOCK_TIMEOUT_MS).toBe(5000);
    expect(MIGRATION_STATEMENT_TIMEOUT_MS).toBe(60_000);
    expect(MIGRATION_IDLE_IN_TRANSACTION_TIMEOUT_MS).toBe(10_000);
    expect(MIGRATION_DEPLOY_KILL_TIMEOUT_MS).toBe(180_000);
    expect(MIGRATION_AUTO_RESOLVE_MIN_ELAPSED_MS).toBe(MIGRATION_LOCK_TIMEOUT_MS);
  });

  test('all three settings share one options parameter', () => {
    const parsed = new URL(withMigrationSessionLimits(url));
    expect(parsed.searchParams.get('options')).toBe(
      '-c lock_timeout=5000 -c statement_timeout=60000 -c idle_in_transaction_session_timeout=10000',
    );
  });

  test('replaces its own settings in any spelling, keeps the rest, and is idempotent', () => {
    const merged = withMigrationSessionLimits(
      `${url}?options=-c%20search_path%3Dapp%20-cstatement_timeout%3D1%20--idle_in_transaction_session_timeout%3D2%20-c%20lock_timeout%3D3`,
    );
    expect(new URL(merged).searchParams.get('options')).toBe(
      '-c search_path=app -c lock_timeout=5000 -c statement_timeout=60000 -c idle_in_transaction_session_timeout=10000',
    );
    expect(withMigrationSessionLimits(merged)).toBe(merged);
  });
});

describe('isOnlyAbortedTransactionError', () => {
  test('accepts the engine output of a failure inside an explicit transaction', () => {
    expect(isOnlyAbortedTransactionError(maskedFailure)).toBe(true);
  });

  test('refuses any other error text, or a second line that mentions an error', () => {
    expect(isOnlyAbortedTransactionError('')).toBe(false);
    expect(isOnlyAbortedTransactionError('Error: ERROR: canceling statement due to statement timeout')).toBe(false);
    expect(isOnlyAbortedTransactionError(`${maskedFailure}\nDatabase error code: 55P03`)).toBe(false);
    expect(isOnlyAbortedTransactionError(`${maskedFailure}\nError: P3009`)).toBe(false);
    expect(isOnlyAbortedTransactionError(maskedFailure.replace('current transaction is aborted', 'relation does not exist'))).toBe(false);
  });
});

describe('decideAutoResolve', () => {
  test('resolves when every condition holds', async () => {
    expect(await decide({})).toEqual({ resolve: true, name });
  });

  test('the timing gate is the lock timeout: five seconds passes, less does not', async () => {
    expect(await decide({ child: { elapsedMs: MIGRATION_LOCK_TIMEOUT_MS } })).toEqual({ resolve: true, name });
    const fast = await decide({ child: { elapsedMs: MIGRATION_LOCK_TIMEOUT_MS - 1 } });
    expect(fast).toEqual({ resolve: false, message: expect.stringContaining('faster than the 5s lock timeout') });
  });

  test('a killed child is never resolved, whatever its output says', async () => {
    const killed = await decide({ child: { timedOut: true, status: null, elapsedMs: 180_000 } });
    expect(killed).toEqual({ resolve: false, message: expect.stringContaining('was killed after 180s') });
  });

  test('another error class is not resolved', async () => {
    const other = await decide({ child: { output: `${maskedFailure}\nDatabase error code: 23514` } });
    expect(other).toEqual({ resolve: false, message: expect.stringContaining('other than the aborted-transaction error') });
  });

  test('a second unfinished row, or none, is not resolved', async () => {
    const second: MigrationRow = { ...unfinished, migration_name: '20261021_0002_org_key_sign_challenges' };
    expect(await decide({ rows: [unfinished, second] })).toEqual({ resolve: false, message: expect.stringContaining('2 unfinished') });
    expect(await decide({ rows: [] })).toEqual({ resolve: false, message: expect.stringContaining('0 unfinished') });
  });

  test('a migration without a reviewed object list or with another checksum is not resolved', async () => {
    expect(await decide({ reviewed: new Map() })).toEqual({ resolve: false, message: expect.stringContaining('no reviewed object list') });
    expect(await decide({ rows: [{ ...unfinished, checksum: 'edited' }] })).toEqual({
      resolve: false,
      message: expect.stringContaining('differs from the reviewed one'),
    });
  });

  test('a name with an earlier rolled-back row is never resolved a second time', async () => {
    const earlier: MigrationRow = { ...unfinished, rolled_back_at: new Date(0) };
    expect(await decide({ rows: [earlier, unfinished] })).toEqual({
      resolve: false,
      message: expect.stringContaining('already marked rolled back once'),
    });
  });

  test('a rolled-back row of another name does not count', async () => {
    const other: MigrationRow = { ...unfinished, migration_name: 'other', rolled_back_at: new Date(0) };
    expect(await decide({ rows: [other, unfinished] })).toEqual({ resolve: true, name });
  });

  test('any object of the migration that exists stops it', async () => {
    expect(await decide({ present: ['type KeyCustody'] })).toEqual({
      resolve: false,
      message: expect.stringContaining('1 object(s) of migration'),
    });
  });

  test('no message repeats the child output or a URL', async () => {
    const decisions = await Promise.all([
      decide({ child: { timedOut: true } }),
      decide({ child: { output: 'postgresql://u:pw@h/db Error: boom' } }),
      decide({ child: { elapsedMs: 1 } }),
    ]);
    for (const decision of decisions) {
      if (decision.resolve) throw new Error('expected a stop');
      expect(decision.message).not.toContain('postgresql://');
      expect(decision.message).not.toContain('boom');
    }
  });
});

// The object lists are written by hand from the migrations' SQL. Where those migrations are present in
// the tree, the lists must still be exactly what the SQL creates (this guards a migration edit that adds
// an object without adding it to the list, which would weaken the absence check).
describe('reviewedMigrationObjects against the migration SQL', () => {
  const migrationsRoot = resolve(import.meta.dir, '../packages/db/prisma/migrations');
  const present = [...reviewedMigrationObjects.keys()].filter((migration) => existsSync(join(migrationsRoot, migration)));

  test.skipIf(present.length === 0)('each list is what its migration creates', async () => {
    for (const migration of present) {
      const sql = (await readFile(join(migrationsRoot, migration, 'migration.sql'), 'utf8'))
        .split('\n')
        .filter((line) => !line.trimStart().startsWith('--'))
        .join('\n');
      const names = (pattern: RegExp) => [...sql.matchAll(pattern)].map((match) => match[1]!).sort();
      const objects = reviewedMigrationObjects.get(migration)!;
      expect([...objects.types].sort()).toEqual(names(/CREATE TYPE "([^"]+)"/g));
      expect([...objects.tables].sort()).toEqual(names(/CREATE TABLE "([^"]+)"/g));
      expect([...objects.constraints].sort()).toEqual(names(/(?:ADD )?CONSTRAINT "([^"]+)"/g));
      const columns = [...sql.matchAll(/ALTER TABLE "([^"]+)" ADD COLUMN "([^"]+)"(?:,\s*ADD COLUMN "([^"]+)")?/g)]
        .flatMap((match) => [`${match[1]}.${match[2]}`, ...(match[3] ? [`${match[1]}.${match[3]}`] : [])])
        .sort();
      expect([...objects.columns].sort()).toEqual(columns);
      const primaryKeys = [...sql.matchAll(/CONSTRAINT "([^"]+)" PRIMARY KEY/g)].map((match) => match[1]!);
      expect([...objects.indexes].sort()).toEqual([...names(/CREATE (?:UNIQUE )?INDEX "([^"]+)"/g), ...primaryKeys].sort());
    }
  });
});

// Everything below needs a throwaway Postgres (OPENKEY_TEST_POSTGRES_URL, as the other Postgres-backed
// tests); skipped without one. It drives the real Prisma schema engine against scratch migrations.
const adminUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '..');
const prismaBin = join(root, 'node_modules/.bin/prisma');
const created: string[] = [];
const scratchDirs: string[] = [];

function databaseUrl(database: string): string {
  const parsed = new URL(adminUrl!);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

async function createDatabase(): Promise<string> {
  const database = `auto_resolve_${randomUUID().replaceAll('-', '')}`;
  const admin = new Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${database}`);
  } finally {
    await admin.end();
  }
  created.push(database);
  return databaseUrl(database);
}

afterAll(async () => {
  if (adminUrl && created.length > 0) {
    const admin = new Client({ connectionString: adminUrl });
    await admin.connect();
    try {
      for (const database of created) await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    } finally {
      await admin.end();
    }
  }
  for (const dir of scratchDirs) await rm(dir, { recursive: true, force: true });
});

const baseline = '20260101_0001_create';
const probe = '20260101_0002_probe';

const probeSql = [
  'BEGIN;',
  'LOCK TABLE "probe_a" IN ACCESS EXCLUSIVE MODE;',
  `CREATE TYPE "ProbeKind" AS ENUM ('A');`,
  'CREATE TABLE "probe_b" ("id" integer NOT NULL, CONSTRAINT "probe_b_pkey" PRIMARY KEY ("id"));',
  'ALTER TABLE "probe_a" ADD COLUMN "note" text;',
  'COMMIT;',
  '',
].join('\n');

const probeObjects: MigrationObjects = {
  types: ['ProbeKind'],
  columns: ['probe_a.note'],
  constraints: ['probe_b_pkey'],
  tables: ['probe_b'],
  indexes: ['probe_b_pkey'],
};

interface Scratch {
  dir: string;
  url: string;
  schema: string;
  checksum: string;
  apply: () => Promise<void>;
}

// A project whose baseline migration creates probe_a and whose second migration is `second`, parked until apply().
async function scratch(second: string): Promise<Scratch> {
  const dir = await mkdtemp(join(tmpdir(), 'openkey-auto-resolve-'));
  scratchDirs.push(dir);
  const migrations = join(dir, 'prisma/migrations');
  await mkdir(join(migrations, baseline), { recursive: true });
  await mkdir(join(dir, 'parked', probe), { recursive: true });
  await writeFile(join(dir, 'prisma/schema.prisma'), 'datasource db {\n  provider = "postgresql"\n}\n');
  await writeFile(join(dir, 'prisma.config.ts'), [
    'export default {',
    '  schema: "prisma/schema.prisma",',
    '  migrations: { path: "prisma/migrations" },',
    '  datasource: { url: process.env.DATABASE_URL },',
    '};',
    '',
  ].join('\n'));
  await writeFile(join(migrations, 'migration_lock.toml'), 'provider = "postgresql"\n');
  await writeFile(join(migrations, baseline, 'migration.sql'), 'CREATE TABLE "probe_a" ("id" integer PRIMARY KEY);\n');
  await writeFile(join(dir, 'parked', probe, 'migration.sql'), second);
  return {
    dir,
    url: await createDatabase(),
    schema: join(dir, 'prisma/schema.prisma'),
    checksum: createHash('sha256').update(second).digest('hex'),
    apply: () => rename(join(dir, 'parked', probe), join(migrations, probe)),
  };
}

// `pg` behind the Prisma-style query method the script takes.
function queryClient(client: Client): QueryClient {
  return {
    async $queryRawUnsafe<T>(query: string, ...values: unknown[]) {
      return (await client.query(query, values)).rows as T;
    },
  };
}

async function withClient<T>(url: string, work: (client: Client) => Promise<T>): Promise<T> {
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    return await work(client);
  } finally {
    await client.end();
  }
}

function deploy(scratchProject: Scratch, catalog: ReadonlyMap<string, ReviewedMigration>, timeoutMs?: number) {
  return withClient(scratchProject.url, (client) => migrateDeployWithAutoResolve({
    database: queryClient(client),
    command: process.execPath,
    deployArgs: [prismaBin, 'migrate', 'deploy', '--schema', scratchProject.schema],
    resolveArgs: (migration) => [prismaBin, 'migrate', 'resolve', '--rolled-back', migration, '--schema', scratchProject.schema],
    cwd: scratchProject.dir,
    env: migrationChildEnv({ ...process.env, DATABASE_URL: scratchProject.url }),
    reviewed: catalog,
    timeoutMs,
  }).then(() => '', (error: Error) => error.message));
}

function catalogFor(scratchProject: Scratch, checksum = scratchProject.checksum): ReadonlyMap<string, ReviewedMigration> {
  return new Map([[probe, { checksum, objects: probeObjects }]]);
}

// Another session holds ACCESS EXCLUSIVE on probe_a, so the migration's first LOCK waits and times out.
async function whileProbeIsLocked<T>(scratchProject: Scratch, work: () => Promise<T>): Promise<T> {
  const holder = new Client({ connectionString: scratchProject.url });
  await holder.connect();
  await holder.query('BEGIN');
  await holder.query('LOCK TABLE "probe_a" IN ACCESS EXCLUSIVE MODE');
  try {
    return await work();
  } finally {
    await holder.query('ROLLBACK').catch(() => undefined);
    await holder.end();
  }
}

async function ledger(url: string) {
  return withClient(url, async (client) => (await client.query(
    'SELECT migration_name, finished_at IS NOT NULL AS finished, rolled_back_at IS NOT NULL AS rolled_back FROM "_prisma_migrations" WHERE migration_name = $1 ORDER BY started_at',
    [probe],
  )).rows as Array<{ migration_name: string; finished: boolean; rolled_back: boolean }>);
}

async function present(url: string) {
  return withClient(url, (client) => listPresentMigrationObjects(queryClient(client), probeObjects));
}

describe.skipIf(!adminUrl)('prisma migrate deploy with the narrow auto-resolve, on Postgres', () => {
  async function appliedBaseline(second: string) {
    const project = await scratch(second);
    expect(await deploy(project, new Map())).toBe('');
    await project.apply();
    return project;
  }

  test('a lock timeout inside the explicit transaction leaves nothing, is marked rolled back once, and the next run applies it', async () => {
    const project = await appliedBaseline(probeSql);
    const message = await whileProbeIsLocked(project, () => deploy(project, catalogFor(project)));

    expect(message).toMatch(new RegExp(`^error class unknown \\(aborted transaction\\); migration ${probe} marked rolled back; elapsed \\d+s since the migrate started; retry the deploy$`));
    expect(await present(project.url)).toEqual([]);
    expect(await ledger(project.url)).toEqual([{ migration_name: probe, finished: false, rolled_back: true }]);

    // The next run, with the lock gone, applies it: no second `migrate resolve`, no leftover type to collide with.
    expect(await deploy(project, catalogFor(project))).toBe('');
    expect(await ledger(project.url)).toEqual([
      { migration_name: probe, finished: false, rolled_back: true },
      { migration_name: probe, finished: true, rolled_back: false },
    ]);
    expect((await present(project.url)).sort()).toEqual([
      'column probe_a.note', 'constraint probe_b_pkey', 'index probe_b_pkey', 'table probe_b', 'type ProbeKind',
    ]);
  }, 180_000);

  test('a second failure of the same migration is refused: it was already marked rolled back once', async () => {
    const project = await appliedBaseline(probeSql);
    const first = await whileProbeIsLocked(project, () => deploy(project, catalogFor(project)));
    expect(first).toContain('marked rolled back');
    const second = await whileProbeIsLocked(project, () => deploy(project, catalogFor(project)));

    expect(second).toContain(`migration ${probe} was already marked rolled back once`);
    expect(await ledger(project.url)).toEqual([
      { migration_name: probe, finished: false, rolled_back: true },
      { migration_name: probe, finished: false, rolled_back: false },
    ]);
  }, 180_000);

  test('a checksum that differs from the reviewed one is refused and the row stays failed', async () => {
    const project = await appliedBaseline(probeSql);
    const message = await whileProbeIsLocked(project, () => deploy(project, catalogFor(project, 'not-the-reviewed-checksum')));

    expect(message).toContain('differs from the reviewed one');
    expect(await ledger(project.url)).toEqual([{ migration_name: probe, finished: false, rolled_back: false }]);
  }, 120_000);

  test('an object of the migration that already exists is refused and the row stays failed', async () => {
    const project = await appliedBaseline(probeSql);
    await withClient(project.url, (client) => client.query('CREATE TABLE "probe_b" ("id" integer)'));
    const message = await whileProbeIsLocked(project, () => deploy(project, catalogFor(project)));

    expect(message).toContain(`1 object(s) of migration ${probe} exist after the failure`);
    expect(await ledger(project.url)).toEqual([{ migration_name: probe, finished: false, rolled_back: false }]);
  }, 120_000);

  test('a parse error in the migration file is reported as it is, and leaves nothing', async () => {
    // The engine sends the file as one string, so a syntax error rejects it before BEGIN runs: no masking.
    const project = await appliedBaseline('BEGIN;\nCREATE TABLE "probe_b" ("id" integer);\nSELEC 1;\nCOMMIT;\n');
    const message = await deploy(project, catalogFor(project));

    expect(message).toContain('other than the aborted-transaction error');
    expect(await present(project.url)).toEqual([]);
    expect(await ledger(project.url)).toEqual([{ migration_name: probe, finished: false, rolled_back: false }]);
  }, 120_000);

  test('a runtime error inside the explicit transaction is masked like a lock timeout; the timing gate refuses it', async () => {
    // Same aborted-transaction output as a lock timeout, so the output cannot tell them apart; the
    // five-second gate and the object check are what stop it.
    const project = await appliedBaseline('BEGIN;\nCREATE TABLE "probe_b" ("id" integer);\nSELECT 1/0;\nCOMMIT;\n');
    const message = await deploy(project, catalogFor(project));

    expect(message).toMatch(/^migrate deploy failed after \d+s, faster than the 5s lock timeout/);
    expect(await present(project.url)).toEqual([]);
    expect(await ledger(project.url)).toEqual([{ migration_name: probe, finished: false, rolled_back: false }]);
  }, 120_000);

  test('another unfinished row makes the next deploy fail with another error, which is refused', async () => {
    const project = await appliedBaseline(probeSql);
    await withClient(project.url, (client) => client.query(
      `INSERT INTO "_prisma_migrations" (id, checksum, migration_name, started_at, applied_steps_count)
       VALUES ('failed-earlier', 'x', '20260101_0099_failed_earlier', now(), 0)`,
    ));
    const message = await deploy(project, catalogFor(project));

    expect(message).toContain('other than the aborted-transaction error');
    expect(await ledger(project.url)).toEqual([]);
  }, 120_000);
});

describe.skipIf(!adminUrl)('what happens to the connection of a migration child', () => {
  test('the server applies the three session limits to the migration connection', async () => {
    const url = await createDatabase();
    const limits = await withClient(migrationChildEnv({ DATABASE_URL: url }).DATABASE_URL!, async (client) => {
      const shown = await client.query(
        "SELECT current_setting('lock_timeout') AS lock, current_setting('statement_timeout') AS statement, current_setting('idle_in_transaction_session_timeout') AS idle",
      );
      return shown.rows[0] as { lock: string; statement: string; idle: string };
    });
    expect(limits).toEqual({ lock: '5s', statement: '1min', idle: '10s' });
  });

  test('a connection left idle inside a transaction is ended by the server, which releases its locks', async () => {
    const project = await scratch(probeSql);
    expect(await deploy(project, new Map())).toBe('');
    const idle = new Client({ connectionString: migrationChildEnv({ DATABASE_URL: project.url }).DATABASE_URL });
    idle.on('error', () => undefined); // the server's termination is the point of the test
    await idle.connect();
    await idle.query('BEGIN');
    await idle.query('LOCK TABLE "probe_a" IN ACCESS EXCLUSIVE MODE');

    // Real wall time on purpose: the claim is about a server-side timer, which no fake clock reaches.
    const started = Date.now();
    const bound = await withClient(project.url, async (client) => {
      await client.query("SET lock_timeout = '30s'");
      await client.query('BEGIN');
      await client.query('LOCK TABLE "probe_a" IN ACCESS EXCLUSIVE MODE');
      await client.query('ROLLBACK');
      return Date.now() - started;
    });
    expect(bound).toBeGreaterThanOrEqual(MIGRATION_IDLE_IN_TRANSACTION_TIMEOUT_MS - 1000);
    expect(bound).toBeLessThan(MIGRATION_IDLE_IN_TRANSACTION_TIMEOUT_MS + 8000);
  }, 120_000);

  test('a child that hangs holding a lock is killed with its whole process group, and the lock is released', async () => {
    const project = await scratch(probeSql);
    expect(await deploy(project, new Map())).toBe('');
    // The program the hung child runs: connect, take the lock inside a transaction, then idle forever.
    const holdScript = [
      "import { Client } from 'pg';",
      'const client = new Client({ connectionString: process.env.HOLD_URL });',
      'await client.connect();',
      "await client.query('BEGIN');",
      `await client.query('LOCK TABLE "probe_a" IN ACCESS EXCLUSIVE MODE');`,
      'setInterval(() => undefined, 1000);',
    ].join('\n');

    // `sh -c '...; true'` keeps sh alive as the direct child, so the connection belongs to a grandchild.
    const child = await runCapturedChild('/bin/sh', ['-c', 'exec_bun() { "$BUN" -e "$HOLD_SCRIPT"; }; exec_bun; true'], {
      cwd: root,
      env: { ...process.env, BUN: process.execPath, HOLD_SCRIPT: holdScript, HOLD_URL: project.url },
      timeoutMs: 4000,
    });
    expect(child.timedOut).toBe(true);

    const waited = await withClient(project.url, async (client) => {
      await client.query("SET lock_timeout = '3s'");
      await client.query('BEGIN');
      await client.query('LOCK TABLE "probe_a" IN ACCESS EXCLUSIVE MODE');
      await client.query('ROLLBACK');
      return true;
    });
    expect(waited).toBe(true);
  }, 120_000);
});
