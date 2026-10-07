// Physical checks for 20261007_0001_tinycloud_native_foundation (TC-773).
// `prisma migrate diff` cannot see triggers or CHECK constraints, and the
// consent-withdrawal triggers are what revoke native grants and tokens.

export const nativeDelegationMigration = '20261007_0001_tinycloud_native_foundation';
export const nativeDelegationChecksum = '09bd49921bb76911d9218f20866c88f47bcd88552bffec1b124d71e571ef9a02';

type GuardDatabase = {
  $queryRawUnsafe<T>(query: string, ...values: unknown[]): Promise<T>;
};

export async function assertNativeDelegationSchema(database: GuardDatabase): Promise<void> {
  const rows = await database.$queryRawUnsafe<Array<{
    client_column: boolean;
    generation_columns: number;
    generation_primary_key: boolean;
    request_columns: number;
    preparation_columns: number;
    grant_columns: number;
    status_checks: number;
    grant_refresh_index: boolean;
    grant_client_cascade: boolean;
    withdrawal_function: boolean;
    withdrawal_triggers: number;
    nonce_trigger: boolean;
  }>>(`
    SELECT
      EXISTS (SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'oauth_client'
          AND column_name = 'tinycloudNativeDelegation' AND data_type = 'jsonb') AS client_column,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_native_consent_generation') AS generation_columns,
      EXISTS (SELECT 1 FROM pg_constraint
        WHERE conname = 'tinycloud_native_consent_generation_pkey' AND contype = 'p') AS generation_primary_key,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_native_request') AS request_columns,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_native_preparation') AS preparation_columns,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_native_grant') AS grant_columns,
      (SELECT COUNT(*)::int FROM pg_constraint WHERE contype = 'c' AND conname IN (
        'tinycloud_native_request_status_check',
        'tinycloud_native_request_hosting_check',
        'tinycloud_native_request_siwe_nonce_check',
        'tinycloud_native_grant_status_check'
      )) AS status_checks,
      to_regclass('public."tinycloud_native_grant_refreshTokenHash_key"') IS NOT NULL AS grant_refresh_index,
      EXISTS (SELECT 1 FROM pg_constraint
        WHERE conname = 'tinycloud_native_grant_clientId_fkey' AND contype = 'f' AND confdeltype = 'c') AS grant_client_cascade,
      to_regprocedure('public.tinycloud_native_withdraw_consent()') IS NOT NULL AS withdrawal_function,
      (SELECT COUNT(*)::int FROM pg_trigger
        WHERE tgrelid = to_regclass('public.oauth_consent')
          AND NOT tgisinternal
          AND tgenabled <> 'D'
          AND tgfoid = to_regprocedure('public.tinycloud_native_withdraw_consent()')
          AND tgname IN ('tinycloud_native_consent_deleted', 'tinycloud_native_consent_scope_withdrawn')) AS withdrawal_triggers,
      EXISTS (SELECT 1 FROM pg_trigger
        WHERE tgrelid = to_regclass('public.tinycloud_native_request')
          AND NOT tgisinternal
          AND tgenabled <> 'D'
          AND tgname = 'tinycloud_native_request_nonce_immutable'
          AND tgfoid = to_regprocedure('public.tinycloud_native_request_nonce_immutable()')) AS nonce_trigger
  `);
  const verified = rows[0];
  if (
    !verified?.client_column ||
    verified.generation_columns !== 3 ||
    !verified.generation_primary_key ||
    verified.request_columns !== 25 ||
    verified.preparation_columns !== 11 ||
    verified.grant_columns !== 24 ||
    verified.status_checks !== 4 ||
    !verified.grant_refresh_index ||
    !verified.grant_client_cascade ||
    !verified.withdrawal_function ||
    verified.withdrawal_triggers !== 2 ||
    !verified.nonce_trigger
  ) {
    throw new Error(`TC-773 native delegation schema verification failed: ${JSON.stringify(verified)}`);
  }
}
