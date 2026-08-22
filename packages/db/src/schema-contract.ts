export type MigrationRecord = {
  migration_name: string;
  checksum: string;
  finished_at: Date | null;
  rolled_back_at: Date | null;
};

// These migrations add every database field used by the candidate API client
// after the reviewed production baseline. TC-488 is intentionally absent: it
// is a separately authorized destructive custody cutover, not a prerequisite
// for this API image to serve traffic safely.
export const requiredRuntimeMigrationChecksums = new Map<string, string>([
  ['20260714_origin_main_schema_catchup', '0d55069dce6b6d51b42ab95bd813a8698261d4de32e64a0c702f4d4a17263a09'],
  ['20260805_0001_canonical_tinycloud_key', '65b81dce28ab9dc8847defa78f986abe000243cfd027879238f55efee825cfae'],
  ['20260805_0002_tinycloud_manage_key_app_preferences', '035b642532adfc98351141a578ff675c5f67fbde41da6e208e8d3bbbc336d972'],
  ['20260805_0003_tinycloud_manage_key_global_preference', '4cf2225e80626f98b826225fbed45f6166b10ec7c3999dcb7b272ae2da06ab0e'],
  ['20260806_0001_tinycloud_manage_key_lifecycle', '2ae19ab7c9267d704d17578c8613c17b737d1706acc0b2e48dd3f4a4661d35bd'],
  ['20260814_0001_share_device_authorization', '81bc814a59b2d7604c5d40490e1c96290a7532b70751c60b44b60e3e4b1e199a'],
]);

export type SchemaContractDatabase = {
  $queryRawUnsafe<T>(query: string): Promise<T>;
};

export type SchemaContractResult =
  | { ready: true }
  | { ready: false; reason: 'migration-missing' | 'migration-unfinished' | 'migration-rolled-back' | 'migration-checksum-mismatch' | 'migration-query-failed' };

export async function checkRuntimeSchemaContract(
  database: SchemaContractDatabase,
): Promise<SchemaContractResult> {
  let migrations: MigrationRecord[];
  try {
    migrations = await database.$queryRawUnsafe<MigrationRecord[]>(
      'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations"',
    );
  } catch {
    return { ready: false, reason: 'migration-query-failed' };
  }

  for (const [name, checksum] of requiredRuntimeMigrationChecksums) {
    const migration = migrations.find((candidate) => candidate.migration_name === name);
    if (!migration) return { ready: false, reason: 'migration-missing' };
    if (!migration.finished_at) return { ready: false, reason: 'migration-unfinished' };
    if (migration.rolled_back_at) return { ready: false, reason: 'migration-rolled-back' };
    if (migration.checksum !== checksum) return { ready: false, reason: 'migration-checksum-mismatch' };
  }

  return { ready: true };
}
