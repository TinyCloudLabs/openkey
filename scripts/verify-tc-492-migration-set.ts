#!/usr/bin/env bun

import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

import { createPrismaClient } from '../packages/db/src/index';

const baseline = {
  name: '20260714_origin_main_schema_catchup',
  checksum: '0d55069dce6b6d51b42ab95bd813a8698261d4de32e64a0c702f4d4a17263a09',
};

const expected = [
  ['20260805_0001_canonical_tinycloud_key', '65b81dce28ab9dc8847defa78f986abe000243cfd027879238f55efee825cfae'],
  ['20260805_0002_tinycloud_manage_key_app_preferences', '035b642532adfc98351141a578ff675c5f67fbde41da6e208e8d3bbbc336d972'],
  ['20260805_0003_tinycloud_manage_key_global_preference', '4cf2225e80626f98b826225fbed45f6166b10ec7c3999dcb7b272ae2da06ab0e'],
  ['20260806_0001_tinycloud_manage_key_lifecycle', '2ae19ab7c9267d704d17578c8613c17b737d1706acc0b2e48dd3f4a4661d35bd'],
  ['20260806_0002_remove_organization_key_custody', 'ecf68b38f136da32292c250566d3094d1f8eb0b89c855fd8543adf4544ec7ac6'],
] as const;

const acceptedHistoricalChecksums = new Map([
  ['0_init', new Set(['58d6293e97ed14dc7648778c095fbe47f07ed91165090657d36b4ff343a0478c'])],
]);

type Migration = {
  migration_name: string;
  checksum: string;
  finished_at: Date | null;
  rolled_back_at: Date | null;
};

async function main() {
  const phase = process.argv[2];
  if (phase !== 'pre' && phase !== 'post') throw new Error('usage: verify-tc-492-migration-set.ts <pre|post>');

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl?.match(/^postgres(ql)?:\/\//)) throw new Error('DATABASE_URL must be PostgreSQL');

  const migrationRoot = path.resolve(import.meta.dir, '../packages/db/prisma/migrations');
  const directories = (await readdir(migrationRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  const filesystemChecksums = new Map<string, string>();
  for (const name of directories) {
    const sql = await readFile(path.join(migrationRoot, name, 'migration.sql'));
    filesystemChecksums.set(name, createHash('sha256').update(sql).digest('hex'));
  }

  for (const [name, checksum] of expected) {
    const actual = filesystemChecksums.get(name);
    if (actual !== checksum) throw new Error(`reviewed migration checksum mismatch: ${name}`);
  }

  const prisma = createPrismaClient({ connectionString: databaseUrl });
  try {
    const migrations = await prisma.$queryRawUnsafe<Migration[]>(
      'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations" ORDER BY migration_name',
    );
    const marker = migrations.find((row) => row.migration_name === baseline.name);
    if (!marker?.finished_at || marker.rolled_back_at || marker.checksum !== baseline.checksum) {
      throw new Error(`production baseline marker ${baseline.name} is missing or invalid`);
    }

    const unresolved = migrations.filter((row) => !row.finished_at && !row.rolled_back_at);
    if (unresolved.length) {
      throw new Error(`unresolved migration failures: ${unresolved.map((row) => row.migration_name).join(', ')}`);
    }

    const successful = migrations.filter((row) => row.finished_at && !row.rolled_back_at);
    const unknown = successful.filter((row) => !filesystemChecksums.has(row.migration_name));
    if (unknown.length) {
      throw new Error(`database contains migrations absent from the candidate: ${unknown.map((row) => row.migration_name).join(', ')}`);
    }
    for (const row of successful) {
      const currentChecksum = filesystemChecksums.get(row.migration_name);
      const acceptedHistorical = acceptedHistoricalChecksums.get(row.migration_name)?.has(row.checksum) ?? false;
      if (row.checksum !== currentChecksum && !acceptedHistorical) {
        throw new Error(`stored migration checksum differs from the candidate: ${row.migration_name}`);
      }
    }
    const applied = new Set(successful.map((row) => row.migration_name));
    const pending = directories.filter((name) => !applied.has(name));
    const expectedNames = expected.map(([name]) => name);
    const wanted = phase === 'pre' ? expectedNames : [];
    if (JSON.stringify(pending) !== JSON.stringify(wanted)) {
      throw new Error(`unexpected pending migration set for ${phase}: ${pending.join(', ') || '(none)'}`);
    }

    for (const [name, checksum] of expected) {
      const row = migrations.find((migration) => migration.migration_name === name);
      if (phase === 'pre' && row?.finished_at && !row.rolled_back_at) {
        throw new Error(`reviewed migration was already applied before cutover: ${name}`);
      }
      if (phase === 'post' && (!row?.finished_at || row.rolled_back_at || row.checksum !== checksum)) {
        throw new Error(`reviewed migration was not applied with the accepted checksum: ${name}`);
      }
    }

    console.log(JSON.stringify({
      schema: 'openkey.tc492.migration-set.v1',
      phase,
      baseline,
      expected: expected.map(([name, checksum]) => ({ name, checksum })),
      pending,
    }));
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
