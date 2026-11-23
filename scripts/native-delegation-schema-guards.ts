// Physical checks for the TC-773 native delegation migrations:
// 20261007_0001_tinycloud_native_foundation, the additive
// 20261007_0002_native_preparation_host, the token guard triggers of
// 20261007_0003_tinycloud_native_token_guard, sign-in columns from
// 20261012_0001_signin_polish_hints_branding, and session proof replay
// protection from 20261012_0002_native_session_proof_jti, and the step-up
// table and grant-revocation trigger of 20261121_0001_native_stepup.
// The standing-lease migration also queues node revocation when native consent or a grant ends.
// `prisma migrate diff` cannot see triggers or CHECK constraints, and the
// consent-withdrawal triggers are what revoke native grants and tokens.

export const nativeDelegationMigration = '20261007_0001_tinycloud_native_foundation';
export const nativeDelegationChecksum = '09bd49921bb76911d9218f20866c88f47bcd88552bffec1b124d71e571ef9a02';
export const nativePreparationHostMigration = '20261007_0002_native_preparation_host';
export const nativePreparationHostChecksum = '32b154ed94aeda7c3e40d8392ea3bc118b83b890c6843b9b9f9be34ce2d20bc8';
export const nativeTokenGuardMigration = '20261007_0003_tinycloud_native_token_guard';
export const nativeTokenGuardChecksum = 'ba9ff8dc9183b12ff39786bdf565d70921c33da6e4865d27ab4cc13591c3b1ff';
export const nativeSessionProofJtiMigration = '20261012_0002_native_session_proof_jti';
export const nativeSessionProofJtiChecksum = 'e3b40f3045fbc715556496226d8b60b7eca318fe58df4ba45392665bfd88ff6b';

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
    preparation_host_column: boolean;
    grant_columns: number;
    status_checks: number;
    request_grant_cascade: boolean;
    grant_refresh_index: boolean;
    grant_client_cascade: boolean;
    withdrawal_function: boolean;
    withdrawal_triggers: number;
    nonce_trigger: boolean;
    token_guard_triggers: number;
    proof_jti_columns: number;
    proof_jti_primary_key: boolean;
    proof_jti_expiry_index: boolean;
    stepup_columns: number;
    stepup_grant_app_index: boolean;
    stepup_grant_cascade: boolean;
    stepup_status_check: boolean;
    stepup_grant_revoked_trigger: boolean;
    stepup_guard_trigger: boolean;
    stepup_delegation_columns: number;
    stepup_delegation_cascade: boolean;
    stepup_revoked_trigger: boolean;
    native_renewal_columns: number;
    native_renewal_lease_cascade: boolean;
    native_renewal_grant_index: boolean;
    native_renewal_stop_triggers: number;
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
      EXISTS (SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_native_preparation'
          AND column_name = 'tinycloudHost' AND data_type = 'text') AS preparation_host_column,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_native_grant') AS grant_columns,
      (SELECT COUNT(*)::int FROM pg_constraint WHERE contype = 'c' AND conname IN (
        'tinycloud_native_request_status_check',
        'tinycloud_native_request_hosting_check',
        'tinycloud_native_request_siwe_nonce_check',
        'tinycloud_native_request_kind_check',
        'tinycloud_native_grant_status_check'
      )) AS status_checks,
      EXISTS (SELECT 1 FROM pg_constraint
        WHERE conname = 'tinycloud_native_request_grantId_fkey' AND contype = 'f' AND confdeltype = 'c') AS request_grant_cascade,
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
          AND tgfoid = to_regprocedure('public.tinycloud_native_request_nonce_immutable()')) AS nonce_trigger,
      (SELECT COUNT(*)::int FROM pg_trigger
        WHERE NOT tgisinternal
          AND tgenabled <> 'D'
          AND ((tgrelid = to_regclass('public.oauth_refresh_token')
                AND tgname = 'tinycloud_native_refresh_token_guard'
                AND tgfoid = to_regprocedure('public.tinycloud_native_refresh_token_guard()'))
            OR (tgrelid = to_regclass('public.oauth_access_token')
                AND tgname = 'tinycloud_native_access_token_guard'
                AND tgfoid = to_regprocedure('public.tinycloud_native_access_token_guard()')))
          AND to_regprocedure('public.tinycloud_native_assert_grant_live(text)') IS NOT NULL) AS token_guard_triggers,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'native_session_proof_jti') AS proof_jti_columns,
      EXISTS (SELECT 1 FROM pg_constraint
        WHERE conname = 'native_session_proof_jti_pkey' AND contype = 'p') AS proof_jti_primary_key,
      to_regclass('public.native_session_proof_jti_expires_at_idx') IS NOT NULL AS proof_jti_expiry_index,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_native_stepup') AS stepup_columns,
      to_regclass('public."tinycloud_native_stepup_grantId_appId_key"') IS NOT NULL AS stepup_grant_app_index,
      EXISTS (SELECT 1 FROM pg_constraint
        WHERE conname = 'tinycloud_native_stepup_grantId_fkey' AND contype = 'f' AND confdeltype = 'c') AS stepup_grant_cascade,
      EXISTS (SELECT 1 FROM pg_constraint
        WHERE conname = 'tinycloud_native_stepup_status_check' AND contype = 'c') AS stepup_status_check,
      EXISTS (SELECT 1 FROM pg_trigger
        WHERE tgrelid = to_regclass('public.tinycloud_native_grant')
          AND NOT tgisinternal
          AND tgenabled <> 'D'
          AND tgname = 'tinycloud_native_stepup_grant_revoked'
          AND tgfoid = to_regprocedure('public.tinycloud_native_stepup_grant_revoked()')) AS stepup_grant_revoked_trigger,
      EXISTS (SELECT 1 FROM pg_trigger
        WHERE tgrelid = to_regclass('public.tinycloud_native_stepup')
          AND NOT tgisinternal
          AND tgenabled <> 'D'
          AND tgname = 'tinycloud_native_stepup_guard'
          AND tgfoid = to_regprocedure('public.tinycloud_native_stepup_guard()')) AS stepup_guard_trigger,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_native_stepup_delegation') AS stepup_delegation_columns,
      EXISTS (SELECT 1 FROM pg_constraint
        WHERE conname = 'tinycloud_native_stepup_delegation_grantId_appId_fkey' AND contype = 'f' AND confdeltype = 'c') AS stepup_delegation_cascade,
      EXISTS (SELECT 1 FROM pg_trigger
        WHERE tgrelid = to_regclass('public.tinycloud_native_stepup')
          AND NOT tgisinternal
          AND tgenabled <> 'D'
          AND tgname = 'tinycloud_native_stepup_revoked'
          AND tgfoid = to_regprocedure('public.tinycloud_native_stepup_revoked()')) AS stepup_revoked_trigger,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'native_renewal_lease') AS native_renewal_columns,
      EXISTS (SELECT 1 FROM pg_constraint
        WHERE conname = 'native_renewal_lease_leaseCid_fkey' AND contype = 'f' AND confdeltype = 'c') AS native_renewal_lease_cascade,
      to_regclass('public."native_renewal_lease_grantId_key"') IS NOT NULL AS native_renewal_grant_index,
      (SELECT COUNT(*)::int FROM pg_trigger
        WHERE NOT tgisinternal AND tgenabled <> 'D' AND tgfoid = to_regprocedure('public.queue_native_lease_stop()')
          AND ((tgrelid = to_regclass('public.tinycloud_native_request')
                AND tgname IN ('native_request_queue_lease_stop', 'native_request_delete_queue_lease_stop'))
            OR (tgrelid = to_regclass('public.tinycloud_native_grant')
                AND tgname IN ('native_grant_queue_lease_stop', 'native_grant_delete_queue_lease_stop')))) AS native_renewal_stop_triggers
  `);
  const verified = rows[0];
  if (
    !verified?.client_column ||
    verified.generation_columns !== 3 ||
    !verified.generation_primary_key ||
    // 27 native columns plus `reviewerEpoch`, `reviewerSessionId` and `reviewerDeadline` from 20261111_0002_reviewer_apple.
    // ... and `kind`, `grantId` and `appId` from 20261121_0002_native_request_kind.
    // ... and `approvalPasskeyMethod` from 20261121_0005_native_approval_passkey_method.
    // ... and the renewal ask and lease CID from 20261123_0001_native_standing_renewal.
    verified.request_columns !== 36 ||
    verified.preparation_columns !== 13 ||
    !verified.preparation_host_column ||
    // 24 native columns plus reviewer epoch and standing renewal lease CID.
    verified.grant_columns !== 26 ||
    verified.status_checks !== 5 ||
    !verified.request_grant_cascade ||
    !verified.grant_refresh_index ||
    !verified.grant_client_cascade ||
    !verified.withdrawal_function ||
    verified.withdrawal_triggers !== 2 ||
    !verified.nonce_trigger ||
    verified.token_guard_triggers !== 2 ||
    verified.proof_jti_columns !== 3 ||
    !verified.proof_jti_primary_key ||
    !verified.proof_jti_expiry_index ||
    verified.stepup_columns !== 10 ||
    !verified.stepup_grant_app_index ||
    !verified.stepup_grant_cascade ||
    !verified.stepup_status_check ||
    !verified.stepup_grant_revoked_trigger ||
    !verified.stepup_guard_trigger ||
    verified.stepup_delegation_columns !== 11 ||
    !verified.stepup_delegation_cascade ||
    !verified.stepup_revoked_trigger ||
    verified.native_renewal_columns !== 7 ||
    !verified.native_renewal_lease_cascade ||
    !verified.native_renewal_grant_index ||
    verified.native_renewal_stop_triggers !== 4
  ) {
    throw new Error(`TC-773 native delegation schema verification failed: ${JSON.stringify(verified)}`);
  }
}
