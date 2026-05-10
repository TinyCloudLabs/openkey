#!/usr/bin/env bun

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { config } from 'dotenv';
import { PGlite } from '@electric-sql/pglite';
import {
  DEFAULT_PGLITE_DATABASE_URL,
  isPgliteConnectionString,
  resolvePgliteDataDir,
} from '../packages/db/src/pglite-url';

const repoRoot = resolve(import.meta.dir, '..');
const schemaPath = join(repoRoot, 'packages/db/prisma/schema.prisma');
const prismaBin = join(repoRoot, 'node_modules/.bin/prisma');
const metaTable = '_openkey_pglite_meta';

config({ path: join(repoRoot, '.env'), quiet: true });

function getConnectionString() {
  if (process.env.DATABASE_URL) {
    return process.env.DATABASE_URL;
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error('DATABASE_URL environment variable is not set');
  }
  return DEFAULT_PGLITE_DATABASE_URL;
}

function runPrisma(args: string[], options?: { capture?: boolean; allowDiffExit?: boolean }) {
  const result = spawnSync(process.execPath, [prismaBin, ...args], {
    cwd: repoRoot,
    env: process.env,
    encoding: 'utf8',
    stdio: options?.capture ? 'pipe' : 'inherit',
  });

  const status = result.status ?? 1;
  const allowedStatuses = options?.allowDiffExit ? [0, 2] : [0];
  if (!allowedStatuses.includes(status)) {
    const stderr = result.stderr ? `\n${result.stderr}` : '';
    throw new Error(`Prisma command failed: prisma ${args.join(' ')}${stderr}`);
  }

  return result;
}

async function generateDiffSql(fromArgs: string[]) {
  const result = runPrisma(
    [
      'migrate',
      'diff',
      ...fromArgs,
      '--to-schema',
      schemaPath,
      '--script',
      '--exit-code',
    ],
    { capture: true, allowDiffExit: true },
  );

  return result.status === 2 ? result.stdout.trim() : '';
}

async function getMeta(db: PGlite) {
  const tableResult = await db.query<{ exists: boolean }>(
    `select exists (
      select 1
      from information_schema.tables
      where table_schema = 'public' and table_name = '${metaTable}'
    ) as exists`,
  );

  if (!tableResult.rows[0]?.exists) {
    return undefined;
  }

  const rows = await db.query<{ key: string; value: string }>(`select key, value from ${metaTable}`);
  return Object.fromEntries(rows.rows.map((row) => [row.key, row.value]));
}

async function ensureEmptyOrManaged(db: PGlite, meta: Record<string, string> | undefined) {
  if (meta) {
    return;
  }

  const tables = await db.query<{ table_name: string }>(
    `select table_name
      from information_schema.tables
      where table_schema = 'public'
        and table_type = 'BASE TABLE'
        and table_name <> '${metaTable}'`,
  );

  if (tables.rows.length > 0) {
    throw new Error(
      `PGlite database already has tables but no OpenKey schema marker. Remove the database directory and rerun db:push.`,
    );
  }
}

async function writeMeta(db: PGlite, schemaHash: string, schema: string) {
  await db.exec(`create table if not exists ${metaTable} (key text primary key, value text not null)`);
  await db.query(
    `insert into ${metaTable} (key, value)
      values
        ('schema_hash', $1),
        ('schema', $2)
      on conflict (key) do update set value = excluded.value`,
    [schemaHash, schema],
  );
}

async function pushPglite(connectionString: string) {
  const dataDir = resolvePgliteDataDir(connectionString);
  if (dataDir.startsWith('memory://')) {
    throw new Error('db:push requires a persistent PGlite data directory, not memory://');
  }

  await mkdir(dirname(dataDir), { recursive: true });

  const schema = await readFile(schemaPath, 'utf8');
  const schemaHash = createHash('sha256').update(schema).digest('hex');
  const db = new PGlite(dataDir);
  await db.waitReady;
  process.exitCode = undefined;

  try {
    const meta = await getMeta(db);
    await ensureEmptyOrManaged(db, meta);

    if (meta?.schema_hash === schemaHash) {
      console.log(`PGlite schema is already up to date at ${dataDir}`);
    } else {
      let tempDir: string | undefined;
      const fromArgs = meta?.schema
        ? await (async () => {
            tempDir = await mkdtemp(join(tmpdir(), 'openkey-prisma-'));
            const previousSchemaPath = join(tempDir, 'schema.prisma');
            await writeFile(previousSchemaPath, meta.schema);
            return ['--from-schema', previousSchemaPath];
          })()
        : ['--from-empty'];

      let sql = '';
      try {
        sql = await generateDiffSql(fromArgs);
      } finally {
        if (tempDir) {
          await rm(tempDir, { recursive: true, force: true });
        }
      }

      if (sql) {
        await db.exec(sql);
      }
      await writeMeta(db, schemaHash, schema);
      console.log(`PGlite schema pushed to ${dataDir}`);
    }
  } finally {
    await db.close();
    process.exitCode = undefined;
  }

  runPrisma(['generate', '--schema', schemaPath]);
}

async function main() {
  const connectionString = getConnectionString();

  if (!isPgliteConnectionString(connectionString)) {
    runPrisma(['db', 'push', '--schema', schemaPath]);
    return;
  }

  await pushPglite(connectionString);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
