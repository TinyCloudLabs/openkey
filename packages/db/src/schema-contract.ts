export type MigrationRecord = {
  migration_name: string;
  checksum: string;
  finished_at: Date | null;
  rolled_back_at: Date | null;
};

export const allowedPendingDestructiveMigrations = new Set([
  '20260806_0002_remove_organization_key_custody',
]);

// Every committed migration after the reviewed production baseline is required
// by this API image. TC-488 is intentionally absent: it is a separately
// authorized destructive custody cutover, not a prerequisite for this image
// to serve traffic safely.
export const requiredRuntimeMigrationChecksums = new Map<string, string>([
  ['20260714_origin_main_schema_catchup', '0d55069dce6b6d51b42ab95bd813a8698261d4de32e64a0c702f4d4a17263a09'],
  ['20260714_zz_origin_main_db_push_reconciliation', '3dc6bb4976ed50b384ce4d6e48994c5838a3e22169ae42e7b1e366f34da9922c'],
  ['20260715_0001_managed_accounts_phase_a_fix', '0598d6bc6d494313ed2f1871039695097f0ef7a252ce996bdcf32561ac3e6c01'],
  ['20260715_0002_managed_accounts_registration_api', '56eeb606148140022a99a1b9c34f26e0b1842c854f0dee58549aa8cbb99220a0'],
  ['20260715_0003_managed_accounts_eject_api', '050a631b72c912bcafcdc532304aa1fbd7c4ca64c36059797a8dda21c46af601'],
  ['20260715_0004_managed_accounts_webhooks', '25da0b570f7d20574de853e1e6588e7159a2b42338f3c249eee531ef4a13e1c7'],
  ['20260720_0001_tenant_managed_email_accounts', '96bbe8f209578c073a0860022967ffbfe6640096a0b3dc01ea0f4d0dbe0899d4'],
  ['20260720_0002_management_credential_default', 'a18f445021e43ceb45fe5069aa8b8f3759bbc28d96864f54ba48f98673308ce1'],
  ['20260720_0003_tenant_managed_account_guard_fixes', '805ca8e03eafb136775433b015b11703e309c911ddf328972674f8d815ce8883'],
  ['20260720_0004_drop_registration_intent', 'a4bf0d3159ddd9654979c7ba2da7982614de9ef1963ae1bd2beaf336f1c890e8'],
  ['20260721_0001_better_auth_1_6_oauth_refresh_tokens', '2ac646166417ddd1996e393b07a2c32596a8b77c3c80670b60e60565bf56988a'],
  ['20260728_0001_oauth_tenant_lifecycle_guard', 'f14cb9c5e0660c9b81e61382bba6cada2c818b37563504c120fb61ddedbed377'],
  ['20260728_0002_coordinationos_session_grants', 'a7f7d2370105a2c5b36ffda72abda130dfe2aa3e7a15066014cbbcf802a02c27'],
  ['20260730_0001_oauth_client_tinycloud_session_policy', 'fdf337855fc77fe7fefa406353a12145d3e0a6bcb17f3b8f1ad8b176ebd5de43'],
  ['20260731051724_add_nostr_keys_and_grants', 'bd85ec78c8101b2aa689951a758ea8a880511adf1303296fe4bd63dc629d73c2'],
  ['20260805_0001_canonical_tinycloud_key', '65b81dce28ab9dc8847defa78f986abe000243cfd027879238f55efee825cfae'],
  ['20260805_0002_tinycloud_manage_key_app_preferences', '035b642532adfc98351141a578ff675c5f67fbde41da6e208e8d3bbbc336d972'],
  ['20260805_0003_tinycloud_manage_key_global_preference', '4cf2225e80626f98b826225fbed45f6166b10ec7c3999dcb7b272ae2da06ab0e'],
  ['20260806_0001_tinycloud_manage_key_lifecycle', '2ae19ab7c9267d704d17578c8613c17b737d1706acc0b2e48dd3f4a4661d35bd'],
  ['20260814_0001_share_device_authorization', '81bc814a59b2d7604c5d40490e1c96290a7532b70751c60b44b60e3e4b1e199a'],
]);

export type SchemaContractDatabase = {
  $queryRawUnsafe<T>(query: string, ...values: string[]): Promise<T>;
};

export type SchemaContractResult =
  | { ready: true }
  | { ready: false; reason: 'migration-missing' | 'migration-unfinished' | 'migration-rolled-back' | 'migration-checksum-mismatch' | 'migration-query-failed' };

export async function checkRuntimeSchemaContract(
  database: SchemaContractDatabase,
): Promise<SchemaContractResult> {
  let migrations: MigrationRecord[];
  try {
    const names = [...requiredRuntimeMigrationChecksums.keys()];
    const placeholders = names.map((_, index) => `$${index + 1}`).join(', ');
    migrations = await database.$queryRawUnsafe<MigrationRecord[]>(
      `SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations" WHERE migration_name IN (${placeholders})`,
      ...names,
    );
  } catch {
    return { ready: false, reason: 'migration-query-failed' };
  }

  for (const [name, checksum] of requiredRuntimeMigrationChecksums) {
    const records = migrations.filter((candidate) => candidate.migration_name === name);
    if (records.length === 0) return { ready: false, reason: 'migration-missing' };

    // Prisma can retain more than one row after an interrupted attempt and a
    // later retry. Do not let an unordered query hide the failed attempt.
    for (const migration of records) {
      if (!migration.finished_at) return { ready: false, reason: 'migration-unfinished' };
      if (migration.rolled_back_at) return { ready: false, reason: 'migration-rolled-back' };
      if (migration.checksum !== checksum) return { ready: false, reason: 'migration-checksum-mismatch' };
    }
  }

  return { ready: true };
}
