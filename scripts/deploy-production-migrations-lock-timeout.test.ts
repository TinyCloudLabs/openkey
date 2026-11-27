import { afterAll, describe, expect, spyOn, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from 'pg';
import {
  MIGRATION_LOCK_TIMEOUT_MS,
  migrationChildEnv,
  withMigrationLockTimeout,
} from './deploy-production-migrations';

const lockOption = 'options=-c%20lock_timeout%3D5000';
const limitOptions =
  'options=-c%20lock_timeout%3D5000%20-c%20statement_timeout%3D60000%20-c%20idle_in_transaction_session_timeout%3D10000';
const url = 'postgresql://deploy:s3cret%40pw@db.internal:5432/openkey';

describe('withMigrationLockTimeout', () => {
  test('the timeout is five seconds', () => {
    expect(MIGRATION_LOCK_TIMEOUT_MS).toBe(5000);
  });

  test('adds an encoded options parameter and leaves the rest of the URL byte for byte', () => {
    expect(withMigrationLockTimeout(url)).toBe(`${url}?${lockOption}`);
  });

  test('keeps the other query parameters and appends options', () => {
    expect(withMigrationLockTimeout(`${url}?sslmode=require&connection_limit=2`)).toBe(
      `${url}?sslmode=require&connection_limit=2&${lockOption}`,
    );
  });

  test('merges with options the URL already carries instead of overwriting them', () => {
    const merged = withMigrationLockTimeout(`${url}?options=-c%20search_path%3Dapp&sslmode=require`);
    const parsed = new URL(merged);
    expect(parsed.searchParams.get('sslmode')).toBe('require');
    expect(parsed.searchParams.getAll('options')).toEqual(['-c search_path=app -c lock_timeout=5000']);
  });

  test('replaces an existing lock_timeout in any spelling and keeps the other settings', () => {
    for (const existing of ['-c lock_timeout=600000', '-clock_timeout=0', '--lock_timeout=1h']) {
      const merged = withMigrationLockTimeout(
        `${url}?options=${encodeURIComponent(`-c statement_timeout=0 ${existing}`)}`,
      );
      expect(new URL(merged).searchParams.getAll('options')).toEqual([
        '-c statement_timeout=0 -c lock_timeout=5000',
      ]);
    }
  });

  test('is idempotent', () => {
    const once = withMigrationLockTimeout(`${url}?sslmode=require&options=-c%20search_path%3Dapp`);
    expect(withMigrationLockTimeout(once)).toBe(once);
    expect(withMigrationLockTimeout(withMigrationLockTimeout(url))).toBe(withMigrationLockTimeout(url));
  });

  test('a # in the URL fails fast with a fixed message that does not repeat the URL', () => {
    const withHash = 'postgresql://deploy:pa#ss-secret@db.internal:5432/openkey';
    let message = '';
    try {
      withMigrationLockTimeout(withHash);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toBe('DATABASE_URL contains "#"; percent-encode it as %23 so the migration lock timeout can be added');
    expect(message).not.toContain('secret');
  });
});

describe('migrationChildEnv', () => {
  test('puts the timeout on DATABASE_URL, keeps every other variable and does not mutate its input', () => {
    const input = { DATABASE_URL: url, PATH: '/usr/bin', OTHER: 'x' } as NodeJS.ProcessEnv;
    const child = migrationChildEnv(input);
    expect(child.DATABASE_URL).toBe(`${url}?${limitOptions}`);
    expect(child.PATH).toBe('/usr/bin');
    expect(child.OTHER).toBe('x');
    expect(input.DATABASE_URL).toBe(url);
  });

  test('an environment without DATABASE_URL is returned as it is', () => {
    const input = { PATH: '/usr/bin' } as NodeJS.ProcessEnv;
    expect(migrationChildEnv(input)).toBe(input);
  });

  test('prints nothing, so the URL and its password never reach a log', () => {
    const spies = [spyOn(console, 'log'), spyOn(console, 'error'), spyOn(console, 'warn'), spyOn(console, 'info')];
    try {
      migrationChildEnv({ DATABASE_URL: url } as NodeJS.ProcessEnv);
      withMigrationLockTimeout(`${url}?options=-c%20lock_timeout%3D1`);
      for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });
});

// The proof that Prisma's schema engine, at the version this repository pins, honours the `options`
// parameter: a migration whose ALTER TABLE has to wait for a lock held by another session fails with
// SQLSTATE 55P03 after about five seconds, and without the parameter it keeps waiting. Needs a
// throwaway Postgres (OPENKEY_TEST_POSTGRES_URL, as the other Postgres-backed tests); skipped without one.
const adminUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '..');
const prismaBin = join(root, 'node_modules/.bin/prisma');
const created: string[] = [];
const scratchDirs: string[] = [];

function databaseUrl(name: string): string {
  const parsed = new URL(adminUrl!);
  parsed.pathname = `/${name}`;
  return parsed.toString();
}

async function createDatabase(): Promise<string> {
  const name = `lock_timeout_${randomUUID().replaceAll('-', '')}`;
  const admin = new Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${name}`);
  } finally {
    await admin.end();
  }
  created.push(name);
  return name;
}

// A one-table project whose second migration alters the table, so a lock on the table blocks it.
async function scratchProject(): Promise<{ dir: string; applySecond: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'openkey-lock-timeout-'));
  scratchDirs.push(dir);
  const migrations = join(dir, 'prisma/migrations');
  await mkdir(join(migrations, '20260101_0001_create'), { recursive: true });
  await mkdir(join(dir, 'parked/20260101_0002_alter'), { recursive: true });
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
  await writeFile(join(migrations, '20260101_0001_create/migration.sql'), 'CREATE TABLE lock_probe (id integer PRIMARY KEY);\n');
  await writeFile(join(dir, 'parked/20260101_0002_alter/migration.sql'), 'ALTER TABLE lock_probe ADD COLUMN note text;\n');
  return {
    dir,
    applySecond: () => rename(join(dir, 'parked/20260101_0002_alter'), join(migrations, '20260101_0002_alter')),
  };
}

function migrateDeploy(dir: string, env: NodeJS.ProcessEnv) {
  return Bun.spawn([process.execPath, prismaBin, 'migrate', 'deploy', '--schema', join(dir, 'prisma/schema.prisma')], {
    cwd: dir,
    env,
    stdout: 'pipe',
    stderr: 'pipe',
  });
}

async function finished(child: Bun.Subprocess<'ignore', 'pipe', 'pipe'>) {
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { output: stdout + stderr, exitCode };
}

afterAll(async () => {
  if (adminUrl && created.length > 0) {
    const admin = new Client({ connectionString: adminUrl });
    await admin.connect();
    try {
      for (const name of created) await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    } finally {
      await admin.end();
    }
  }
  for (const dir of scratchDirs) await rm(dir, { recursive: true, force: true });
});

describe.skipIf(!adminUrl)('prisma migrate deploy through the migration environment, on Postgres', () => {
  async function blockedScenario(useLockTimeout: boolean) {
    const name = await createDatabase();
    const url = databaseUrl(name);
    const { dir, applySecond } = await scratchProject();
    const first = await finished(migrateDeploy(dir, migrationChildEnv({ ...process.env, DATABASE_URL: url })));
    expect(first.exitCode, first.output).toBe(0);
    await applySecond();

    const holder = new Client({ connectionString: url });
    await holder.connect();
    await holder.query('BEGIN');
    await holder.query('LOCK TABLE lock_probe IN ACCESS EXCLUSIVE MODE');
    const started = Date.now();
    const env = useLockTimeout
      ? migrationChildEnv({ ...process.env, DATABASE_URL: url })
      : { ...process.env, DATABASE_URL: url };
    const child = migrateDeploy(dir, env);
    return { child, holder, started, url };
  }

  test('a migration that has to wait for a lock fails with 55P03 after about five seconds', async () => {
    const { child, holder, started } = await blockedScenario(true);
    try {
      const { output, exitCode } = await finished(child);
      const elapsed = Date.now() - started;
      expect(exitCode).not.toBe(0);
      expect(output).toContain('55P03');
      expect(output).toContain('lock timeout');
      expect(elapsed).toBeGreaterThanOrEqual(4500);
      expect(elapsed).toBeLessThan(30_000);
    } finally {
      await holder.query('ROLLBACK').catch(() => undefined);
      await holder.end();
    }
  }, 120_000);

  test('without the parameter the same migration keeps waiting, and applies once the lock is released', async () => {
    const { child, holder, url } = await blockedScenario(false);
    try {
      let exited = false;
      void child.exited.then(() => { exited = true; });
      // Real wall time on purpose: the claim is that the server-side lock wait outlasts the five seconds
      // the other test sees it fail at, and no fake clock reaches a wait inside Postgres.
      await Bun.sleep(9000);
      expect(exited).toBe(false);
      await holder.query('ROLLBACK');
      const { output, exitCode } = await finished(child);
      expect(exitCode, output).toBe(0);
      const check = new Client({ connectionString: url });
      await check.connect();
      try {
        const column = await check.query("SELECT 1 FROM information_schema.columns WHERE table_name = 'lock_probe' AND column_name = 'note'");
        expect(column.rowCount).toBe(1);
      } finally {
        await check.end();
      }
    } finally {
      await holder.query('ROLLBACK').catch(() => undefined);
      await holder.end().catch(() => undefined);
    }
  }, 120_000);
});
