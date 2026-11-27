#!/usr/bin/env bun

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rename, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createPrismaClient } from '../packages/db/src/index';
import {
  assertNativeDelegationSchema,
  nativeDelegationChecksum,
  nativeDelegationMigration,
  nativePreparationHostChecksum,
  nativePreparationHostMigration,
  nativeSessionProofJtiChecksum,
  nativeSessionProofJtiMigration,
  nativeTokenGuardChecksum,
  nativeTokenGuardMigration,
} from './native-delegation-schema-guards';

const repoRoot = resolve(import.meta.dir, '..');
const migrationsDir = join(repoRoot, 'packages/db/prisma/migrations');
const prismaSchema = join(repoRoot, 'packages/db/prisma/schema.prisma');
const prismaBin = join(repoRoot, 'node_modules/.bin/prisma');

const baselineMigration = '20260714_origin_main_schema_catchup';
const baselineChecksum = '0d55069dce6b6d51b42ab95bd813a8698261d4de32e64a0c702f4d4a17263a09';
const tc488Migration = '20260806_0002_remove_organization_key_custody';
const tc492AdditiveMigrations: ReadonlyMap<string, string> = new Map([
  ['20260805_0001_canonical_tinycloud_key', '65b81dce28ab9dc8847defa78f986abe000243cfd027879238f55efee825cfae'],
  ['20260805_0002_tinycloud_manage_key_app_preferences', '035b642532adfc98351141a578ff675c5f67fbde41da6e208e8d3bbbc336d972'],
  ['20260805_0003_tinycloud_manage_key_global_preference', '4cf2225e80626f98b826225fbed45f6166b10ec7c3999dcb7b272ae2da06ab0e'],
  ['20260806_0001_tinycloud_manage_key_lifecycle', '2ae19ab7c9267d704d17578c8613c17b737d1706acc0b2e48dd3f4a4661d35bd'],
]);
const deviceMigration = '20260814_0001_share_device_authorization';
const deviceChecksum = '81bc814a59b2d7604c5d40490e1c96290a7532b70751c60b44b60e3e4b1e199a';
const brokerMigration = '20261005_0001_delegation_code_broker';
const brokerChecksum = 'cc7dcc5365251f6b7c14caf38a892c998a28eb7c998531b7c3b669f4744744df';
const signinPolishMigration = '20261012_0001_signin_polish_hints_branding';
const signinPolishChecksum = 'd09960dda6ae76472c61629283b4030131d47b5f0f5cd7d79a3d02c0c5bf0e96';
const googleLinkStepUpMigration = '20261015_0001_google_link_step_up';
const googleLinkStepUpChecksum = '4848695c2de0e91f66e9e05e4ffa9537bfb62685cc37a925db121d1e7c3c0c4c';
const appleSocialIdentityMigration = '20261015_0002_apple_social_identity';
const appleSocialIdentityChecksum = '5d98152596b3d2bc66dedad4128e77100cc056cefb7ca33d466a1f74c7cea8ba';
const appleSocialContinuationMigration = '20261015_0003_apple_social_continuation';
const appleSocialContinuationChecksum = '52ade4b7b47f44a4ee4638cb33a28fc56a54856801b44b65c4e3dc3eb2beb953';
const preparedHandoffMigration = '20261016_0001_prepared_siwe_handoff';
const preparedHandoffChecksum = '645d931e10dbd068da7f7243dcbe995f1af6f0e339b98d082264c8153bfec9ec';
const appSignInDayMigration = '20261019_0001_app_sign_in_day';
const appSignInDayChecksum = 'a2f56caea9cd46aebccfb4d369e0223cf8338d07ac685a0dce145b4c3c90bb29';
const tinycloudBootstrapSweepMigration = '20261021_0001_tinycloud_bootstrap_sweep_attempts';
const tinycloudBootstrapSweepChecksum = '905d0105d5b97e75d8855f30cd7e35e80d8034e7ee3051402f81d1efc1bf5edd';
const revokedAccessTokenMigration = '20261026_0001_revoked_access_token';
const revokedAccessTokenChecksum = 'a57958f43b7d1c28c25b38ef358a5392e4b7f9ecf78a979b2c86c8027bd53a30';
const reviewerAccountsMigration = '20261111_0001_reviewer_accounts';
// Reviewed expand-only migrations that may run while TC-488 stays parked.
const preTc488AdditiveMigrations: ReadonlyMap<string, string> = new Map([
  [deviceMigration, deviceChecksum],
  [brokerMigration, brokerChecksum],
  [nativeDelegationMigration, nativeDelegationChecksum],
  [nativePreparationHostMigration, nativePreparationHostChecksum],
  [nativeTokenGuardMigration, nativeTokenGuardChecksum],
  [nativeSessionProofJtiMigration, nativeSessionProofJtiChecksum],
  [signinPolishMigration, signinPolishChecksum],
  [googleLinkStepUpMigration, googleLinkStepUpChecksum],
  [appleSocialIdentityMigration, appleSocialIdentityChecksum],
  [appleSocialContinuationMigration, appleSocialContinuationChecksum],
  [preparedHandoffMigration, preparedHandoffChecksum],
  [appSignInDayMigration, appSignInDayChecksum],
  [tinycloudBootstrapSweepMigration, tinycloudBootstrapSweepChecksum],
  [revokedAccessTokenMigration, revokedAccessTokenChecksum],
  ['20261028_0001_approval_request_results', 'c1d45c495e46e7eaf8a3bb92c06802437c34ca2f63c47d63e2550190b1d8ed8f'],
  ['20261103_0001_delegation_code_claim', 'de705f548d9ffd6bc6a0d669f1156874258f31cc2d3e3584dbf0b49e5b40d992'],
  ['20261103_0002_approval_request_denied', '87d5205193ef11fc87a52325ff703cc9fc14dcec3c2a81ac71408ea5709bfce8'],
  ['20261109_0001_approval_request_approving', '59d59bc76994122d54d3d4564002cab2b01fecf194a12ee688f277b41c90fa6b'],
  ['20261110_0001_apple_notifications', '431fea91f3c4ed37c4a7efef982fc5b88e7dc396bdc9b49633366c7da64fd4ba'],
  ['20261110_0002_passkey_enrolment_provenance', '9123f0159b8d5341a737f665dcd6f3853b80a70e21562163f04c611e11d6c388'],
  ['20261113_0001_approval_request_renewal', '1168755d777b50a32bdc33b6e3b8af5e5838527d9bf2f9edf071fc6923954bd8'],
  ['20261113_0002_renewal_lease', '2dd0af909a1d9660a44e392eb1a0efdec46b5b7d83041ba1da7fe8cd6713d18f'],
  ['20261113_0003_renewal_lease_reservation', 'b9463cc0c23648dbc22b97ebfcd35b415be99da6cc6f6ab8422a46e367b76ce0'],
  [reviewerAccountsMigration, '11196b6dd808c535f5ad66f7a92aff85a12afcd47004e279bc42bbc9d9fa7cf2'],
  ['20261111_0002_reviewer_apple', '60d1032a0ef4805e61101fdfb345b3c6ba8fd395110cf2bdbbb0b1573455d56a'],
  ['20261118_0001_terms_acceptance', 'a2535be69867c0a4c138233c22b2bfae7eda5d950c7d5c22138e25ba6efc3e7c'],
  ['20261119_0001_terms_acceptance_no_delete', 'ea98e5b306af38dfb0145ba915ea38ab6bf8e53a52744fc3039d17964ab807c4'],
  ['20261119_0002_passkey_approval_mode', 'a6e0a4dd2351b7bdddf94013b3340db1ba118f6f2fa0e3b82f58b528e371ba78'],
  ['20261121_0001_native_stepup', 'e83cdd1c6296344b0d3df1559c40dbb9381faaff8e167f98486f27d0551bde3b'],
  ['20261121_0002_native_request_kind', '22823dfea36b42f7ffcfc5da0d333340ed025316e68a95c39f63821181022c23'],
  ['20261121_0003_native_withdraw_stepup_tokens', '0058b9b249016025ce123121ee48ffad03241060d6c708100f9958dd8179cf48'],
  ['20261121_0004_native_stepup_delegation', '71c7f4491f6e63320acb9ef34c76ff54ec0bce2e880764e725b3500fa9c0e6bb'],
  ['20261121_0005_native_approval_passkey_method', '450234c3f53249bd91b0f9d92823d24cd377458e1db114a503c08fe588ccf76e'],
  ['20261122_0001_terms_acceptance_embed_audit', 'b57be1d1b87aca2d43ae5b0447d9a2f6bf7bd840b48a2cd8fc0e0b638897dea1'],
  ['20261123_0001_native_standing_renewal', 'd393544e72a00e8644c9cb044f165fc18be56f5e84fd5b21f189d87a7ed0fbbf'],
  ['20261124_0002_tinycloud_bootstrap_authority', '1dc898a4ffa69aa926fcbd197f00e4543cd9d5afc13c8772f3b3e71386bbb44e'],
  ['20261125_0001_account_setup_request', '4e7aa3d81c35c67126bb04a733eba0e47a9679aeeec9b6330fb824da68a41cee'],
  ['20261125_0002_bootstrap_authority_account_setup', '585f1528893926937e54c73055d96cff060b6e9e82bbb3a67c6066403e7c76a8'],
]);

export type MigrationRow = {
  migration_name: string;
  checksum: string;
  finished_at: Date | null;
  rolled_back_at: Date | null;
};

export function selectProductionMigrationMode(input: {
  migrations: MigrationRow[];
  migrationDirectories: string[];
  managedAccountTableExists: boolean;
}): 'full' | 'pre-tc488-additive' {
  const { migrations, migrationDirectories, managedAccountTableExists } = input;
  const baseline = migrations.find((row) => row.migration_name === baselineMigration);
  if (!baseline?.finished_at || baseline.rolled_back_at || baseline.checksum !== baselineChecksum) {
    throw new Error(`Production baseline marker ${baselineMigration} is missing or invalid`);
  }

  const unresolved = migrations.filter((row) => !row.finished_at && !row.rolled_back_at);
  if (unresolved.length > 0) {
    throw new Error(`Production has unresolved failed migrations: ${unresolved.map((row) => row.migration_name).join(', ')}`);
  }

  const successful = new Set(
    migrations
      .filter((row) => row.finished_at && !row.rolled_back_at)
      .map((row) => row.migration_name),
  );
  const tc488Applied = successful.has(tc488Migration);
  if (tc488Applied && !managedAccountTableExists) return 'full';
  if (tc488Applied || !managedAccountTableExists) {
    throw new Error('Production TC-488 migration history and physical custody schema disagree');
  }

  const knownDirectories = new Set(migrationDirectories);
  const unknownHistory = migrations.filter((row) => !knownDirectories.has(row.migration_name));
  if (unknownHistory.length > 0) {
    throw new Error(`Production contains migration history absent from this checkout: ${unknownHistory.map((row) => row.migration_name).join(', ')}`);
  }

  const pending = migrationDirectories.filter((name) => !successful.has(name));
  const reviewedPending = (name: string) =>
    tc492AdditiveMigrations.has(name) || name === tc488Migration || preTc488AdditiveMigrations.has(name);
  const unexpectedPending = pending.filter((name) => !reviewedPending(name));
  if (
    unexpectedPending.length > 0 ||
    !pending.includes(tc488Migration) ||
    !pending.every(reviewedPending)
  ) {
    throw new Error(`Pre-TC-488 production has an unreviewed pending migration set: ${pending.join(', ')}`);
  }

  for (const [name, checksum] of tc492AdditiveMigrations) {
    const applied = migrations.find(
      (row) => row.migration_name === name && row.finished_at && !row.rolled_back_at,
    );
    if (applied && applied.checksum !== checksum) {
      throw new Error(`Stored migration checksum differs from the reviewed ${name}`);
    }
  }

  for (const [name, checksum] of preTc488AdditiveMigrations) {
    const applied = migrations.find(
      (row) => row.migration_name === name && row.finished_at && !row.rolled_back_at,
    );
    if (applied && applied.checksum !== checksum) {
      throw new Error(`Stored migration checksum differs from the reviewed ${name}`);
    }
  }
  return 'pre-tc488-additive';
}

export function partitionPreTc488Migrations(pendingMigrations: string[]) {
  return {
    apply: pendingMigrations.filter((name) => name !== tc488Migration),
    park: pendingMigrations.filter((name) => name === tc488Migration),
  };
}

type RawQueryClient = {
  $queryRawUnsafe<T = unknown>(query: string, ...values: unknown[]): Promise<T>;
};

const accountTableExistsQuery = `SELECT to_regclass('public.account') IS NOT NULL AS "exists"`;
const duplicateAccountIdentityCountQuery = `
  SELECT count(*)::int AS duplicate_groups FROM (
    SELECT "providerId", "accountId"
    FROM "account"
    GROUP BY "providerId", "accountId"
    HAVING count(*) > 1
  ) AS duplicate_account_identities
`;

// The google-link migration adds a unique index on account(providerId,
// accountId). The check runs before `prisma migrate deploy` and reports only
// the number of duplicate groups.
export async function assertNoDuplicateAccountIdentities(database: RawQueryClient) {
  const table = await database.$queryRawUnsafe<Array<{ exists: boolean }>>(accountTableExistsQuery);
  if (table[0]?.exists !== true) return;
  const rows = await database.$queryRawUnsafe<Array<{ duplicate_groups: number }>>(
    duplicateAccountIdentityCountQuery,
  );
  const duplicateGroups = Number(rows[0]?.duplicate_groups ?? 0);
  if (duplicateGroups > 0) {
    throw new Error(
      `${googleLinkStepUpMigration} cannot run: account has ${duplicateGroups} duplicate (providerId, accountId) groups; resolve them before deploying`,
    );
  }
}

const userTableExistsQuery = `SELECT to_regclass('public."user"') IS NOT NULL AS "exists"`;
const reservedReviewerEmailCountQuery = `
  SELECT count(*)::int AS reserved_users FROM "user"
  WHERE lower(email) IN ('openai-review@tinycloud.xyz', 'google-review@tinycloud.xyz', 'appreview@tinycloud.xyz')
`;

// The reviewer-accounts migration reserves three addresses and raises when a
// user already holds one, which leaves a failed history row. The check runs
// before `prisma migrate deploy` and reports only the number of such users.
export async function assertNoReservedReviewerEmails(database: RawQueryClient) {
  const table = await database.$queryRawUnsafe<Array<{ exists: boolean }>>(userTableExistsQuery);
  if (table[0]?.exists !== true) return;
  const rows = await database.$queryRawUnsafe<Array<{ reserved_users: number }>>(
    reservedReviewerEmailCountQuery,
  );
  const reservedUsers = Number(rows[0]?.reserved_users ?? 0);
  if (reservedUsers > 0) {
    throw new Error(
      `${reviewerAccountsMigration} cannot run: ${reservedUsers} existing user(s) hold a reserved app-review address; resolve them before deploying`,
    );
  }
}

function requirePostgresUrl() {
  const value = process.env.DATABASE_URL;
  if (!value?.match(/^postgres(ql)?:\/\//)) {
    throw new Error('Production migration deployment requires a PostgreSQL DATABASE_URL');
  }
}

// Every migration child process connects with these session settings, set through the connection URL
// in code (no role or database setting is involved):
//  - lock_timeout: a statement that has to wait for a lock held by a live session fails with SQLSTATE
//    55P03 after this long instead of queuing behind it (and blocking every query that queues behind the
//    migration). It bounds only the WAIT for a lock.
//  - statement_timeout: a statement that runs longer than this once it holds its locks fails with 57014
//    (for example the CHECK scan of ethereum_keys at 20261021_0001, which runs under ACCESS EXCLUSIVE).
//  - idle_in_transaction_session_timeout: the server ends a connection that sits idle inside a
//    transaction for this long. A migration file with an explicit BEGIN that fails leaves its connection
//    idle in an aborted transaction, which keeps every lock it took until the connection ends; this
//    bounds that hold if the engine lingers on its error path.
// The `migrate deploy` child is also killed (whole process group) after MIGRATION_DEPLOY_KILL_TIMEOUT_MS,
// so its connections always drop. A killed child is never auto-resolved.
//
// REQUIREMENTS AND RISKS for whoever runs this:
//  - DATABASE_URL must be a DIRECT (not pooled) endpoint. The settings reach the server as a startup
//    parameter, which a pooler such as PgBouncer usually refuses; the connection then fails before any
//    statement runs and nothing is applied.
//  - A migration that holds ACCESS EXCLUSIVE on ethereum_keys while it waits for another table (the
//    reviewed org-custody migrations take all their locks up front to avoid this) can deadlock with
//    application transactions that touch "user" and then ethereum_keys. Run the deploy in a low-traffic
//    window; a deadlock victim is reported (40P01) and, like any failure faster than the lock timeout, is
//    never auto-resolved.
export const MIGRATION_LOCK_TIMEOUT_MS = 5000;
export const MIGRATION_STATEMENT_TIMEOUT_MS = 60_000;
export const MIGRATION_IDLE_IN_TRANSACTION_TIMEOUT_MS = 10_000;
// Three statement timeouts plus the lock waits: far more than the reviewed migrations need, finite.
export const MIGRATION_DEPLOY_KILL_TIMEOUT_MS = 180_000;
// A failure faster than the lock timeout cannot be a lock timeout (nor a statement timeout, which is longer).
export const MIGRATION_AUTO_RESOLVE_MIN_ELAPSED_MS = MIGRATION_LOCK_TIMEOUT_MS;

// Return the URL with each `-c <name>=<value>` setting in its `options` parameter, merged with any
// options the URL already carries (an existing setting of the same name, in any spelling, is replaced,
// everything else is kept) and URL-encoded. Idempotent. Never logs.
// A `#` starts a URL fragment and would be mangled by the merge, so it fails fast with a fixed message.
function withSessionSettings(databaseUrl: string, settings: ReadonlyArray<readonly [string, number]>): string {
  if (databaseUrl.includes('#')) {
    throw new Error('DATABASE_URL contains "#"; percent-encode it as %23 so the migration lock timeout can be added');
  }
  const queryStart = databaseUrl.indexOf('?');
  const base = queryStart === -1 ? databaseUrl : databaseUrl.slice(0, queryStart);
  const segments = queryStart === -1 ? [] : databaseUrl.slice(queryStart + 1).split('&').filter(Boolean);
  const kept: string[] = [];
  const options: string[] = [];
  for (const segment of segments) {
    const separator = segment.indexOf('=');
    const key = separator === -1 ? segment : segment.slice(0, separator);
    if (key !== 'options') {
      kept.push(segment);
      continue;
    }
    let value = separator === -1 ? '' : decodeURIComponent(segment.slice(separator + 1));
    for (const [name] of settings) {
      // Drop `-c name=…`, `-cname=…` and `--name=…`; keep every other setting.
      value = value
        .replace(new RegExp(`(?:^|\\s)-c\\s*${name}=\\S*`, 'g'), ' ')
        .replace(new RegExp(`(?:^|\\s)--${name}=\\S*`, 'g'), ' ');
    }
    value = value.trim();
    if (value !== '') options.push(value);
  }
  for (const [name, value] of settings) options.push(`-c ${name}=${value}`);
  kept.push(`options=${encodeURIComponent(options.join(' '))}`);
  return `${base}?${kept.join('&')}`;
}

export function withMigrationLockTimeout(databaseUrl: string, timeoutMs: number = MIGRATION_LOCK_TIMEOUT_MS): string {
  return withSessionSettings(databaseUrl, [['lock_timeout', timeoutMs]]);
}

// lock_timeout, statement_timeout and idle_in_transaction_session_timeout for the migration connection.
export function withMigrationSessionLimits(databaseUrl: string): string {
  return withSessionSettings(databaseUrl, [
    ['lock_timeout', MIGRATION_LOCK_TIMEOUT_MS],
    ['statement_timeout', MIGRATION_STATEMENT_TIMEOUT_MS],
    ['idle_in_transaction_session_timeout', MIGRATION_IDLE_IN_TRANSACTION_TIMEOUT_MS],
  ]);
}

// The environment of every migration child process: the caller's environment
// with DATABASE_URL carrying the session limits.
export function migrationChildEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const databaseUrl = env.DATABASE_URL;
  if (!databaseUrl) return env;
  return { ...env, DATABASE_URL: withMigrationSessionLimits(databaseUrl) };
}

function run(command: string, args: string[]) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    env: migrationChildEnv(process.env),
    encoding: 'utf8',
    stdio: 'inherit',
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} exited with status ${result.status ?? 1}`);
  }
}

function runBunScript(script: string) {
  run(process.execPath, ['run', script]);
}

// What a reviewed pending migration creates, from its SQL. Used only to prove, before a failed
// migration is marked rolled back, that none of it exists. A pending migration without an entry here
// (and a reviewed checksum in preTc488AdditiveMigrations) is NEVER auto-resolved.
export interface MigrationObjects {
  types: readonly string[];
  columns: readonly string[]; // 'table.column'
  constraints: readonly string[];
  tables: readonly string[];
  indexes: readonly string[];
}

export const reviewedMigrationObjects: ReadonlyMap<string, MigrationObjects> = new Map([
  ['20261021_0001_org_key_custody', {
    types: ['KeyCustody', 'KeyGrantRole'],
    columns: ['ethereum_keys.custody'],
    constraints: [
      'ethereum_keys_custody_org_shape_check',
      'org_keys_pkey', 'org_keys_keyId_fkey',
      'key_grants_pkey', 'key_grants_keyId_fkey', 'key_grants_granteeUserId_fkey',
      'org_key_signature_audits_pkey', 'org_key_signature_audits_keyId_fkey', 'org_key_signature_audits_grantId_fkey',
    ],
    tables: ['org_keys', 'key_grants', 'org_key_signature_audits'],
    indexes: [
      'org_keys_pkey', 'org_keys_orgId_idx',
      'key_grants_pkey', 'key_grants_keyId_idx', 'key_grants_granteeUserId_idx', 'key_grants_one_active_owner_per_key',
      'org_key_signature_audits_pkey', 'org_key_signature_audits_keyId_idx', 'org_key_signature_audits_grantId_idx',
      'org_key_signature_audits_passkeyAssertionHash_key',
    ],
  }],
  ['20261021_0002_org_key_sign_challenges', {
    types: [],
    columns: ['org_key_signature_audits.role', 'org_key_signature_audits.messageKind'],
    constraints: [
      'org_key_sign_challenges_pkey', 'org_key_sign_challenges_userId_fkey',
      'org_key_sign_challenges_keyId_fkey', 'org_key_sign_challenges_grantId_fkey',
    ],
    tables: ['org_key_sign_challenges'],
    indexes: [
      'org_key_sign_challenges_pkey', 'org_key_sign_challenges_nonce_key', 'org_key_sign_challenges_userId_idx',
      'org_key_sign_challenges_keyId_idx', 'org_key_sign_challenges_grantId_idx',
    ],
  }],
  ['20261029_0001_org_registration_proofs', {
    types: [],
    columns: [],
    constraints: [
      'org_key_registration_challenges_pkey', 'org_registration_challenge_consumption_check',
      'org_key_registration_challenges_sessionId_fkey',
      'org_key_registrations_pkey', 'org_key_registrations_keyId_fkey', 'org_key_registrations_grantId_fkey',
    ],
    tables: ['org_key_registration_challenges', 'org_key_registrations'],
    indexes: [
      'org_key_registration_challenges_pkey', 'org_key_registration_challenges_assertionHash_key',
      'org_key_registration_challenges_registrationId_idx', 'org_key_registration_challenges_expiresAt_idx',
      'org_key_registrations_pkey', 'org_key_registrations_keyId_key', 'org_key_registrations_grantId_key',
      'org_key_registrations_jti_key',
    ],
  }],
]);

export interface ReviewedMigration {
  checksum: string;
  objects: MigrationObjects;
}

// The pending migrations that may be auto-resolved: those with an object list AND a reviewed checksum.
export function reviewedAutoResolvableMigrations(): Map<string, ReviewedMigration> {
  const reviewed = new Map<string, ReviewedMigration>();
  for (const [name, objects] of reviewedMigrationObjects) {
    const checksum = preTc488AdditiveMigrations.get(name);
    if (checksum) reviewed.set(name, { checksum, objects });
  }
  return reviewed;
}

export interface QueryClient {
  $queryRawUnsafe<T = unknown>(query: string, ...values: unknown[]): Promise<T>;
}

// Every listed object that exists in the public schema, as 'kind name'.
export async function listPresentMigrationObjects(database: QueryClient, objects: MigrationObjects): Promise<string[]> {
  const rows = await database.$queryRawUnsafe<Array<{ object: string }>>(
    `SELECT 'type ' || typname AS object FROM pg_type
       WHERE typnamespace = 'public'::regnamespace AND typname = ANY($1::text[])
     UNION ALL
     SELECT 'column ' || table_name || '.' || column_name FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name || '.' || column_name = ANY($2::text[])
     UNION ALL
     SELECT 'constraint ' || conname FROM pg_constraint WHERE conname = ANY($3::text[])
     UNION ALL
     SELECT 'table ' || table_name FROM information_schema.tables
       WHERE table_schema = 'public' AND table_name = ANY($4::text[])
     UNION ALL
     SELECT 'index ' || indexname FROM pg_indexes
       WHERE schemaname = 'public' AND indexname = ANY($5::text[])`,
    [...objects.types], [...objects.columns], [...objects.constraints], [...objects.tables], [...objects.indexes],
  );
  return rows.map((row) => row.object);
}

export interface CapturedChild {
  status: number | null;
  output: string;
  elapsedMs: number;
  timedOut: boolean;
}

const CAPTURED_OUTPUT_LIMIT = 1_000_000;

// Run a child process in its own process group, teeing its stdout and stderr to ours while keeping them
// for the auto-resolve decision, and SIGKILL the whole group after timeoutMs so that no grandchild (the
// schema engine) keeps a database connection, and its locks, alive. The timer is real wall time on
// purpose: it bounds a real process.
export function runCapturedChild(
  command: string,
  args: string[],
  options: { cwd: string; env: NodeJS.ProcessEnv; timeoutMs: number },
): Promise<CapturedChild> {
  const { promise, resolve, reject } = Promise.withResolvers<CapturedChild>();
  const started = Date.now();
  const child = spawn(command, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });
  let output = '';
  let timedOut = false;
  const collect = (sink: NodeJS.WriteStream) => (chunk: Buffer) => {
    sink.write(chunk);
    output = (output + chunk.toString('utf8')).slice(-CAPTURED_OUTPUT_LIMIT);
  };
  child.stdout.on('data', collect(process.stdout));
  child.stderr.on('data', collect(process.stderr));
  const timer = setTimeout(() => {
    timedOut = true;
    try {
      if (child.pid !== undefined) process.kill(-child.pid, 'SIGKILL');
    } catch {
      // The group is already gone.
    }
  }, options.timeoutMs);
  child.once('error', (error) => {
    clearTimeout(timer);
    reject(error);
  });
  child.once('close', (status) => {
    clearTimeout(timer);
    resolve({ status, output, elapsedMs: Date.now() - started, timedOut });
  });
  return promise;
}

// The one error the schema engine prints when a statement inside a migration's own BEGIN ... COMMIT
// fails: it then sends its next command on the aborted transaction, and that error replaces the real
// one (a lock timeout 55P03, a statement timeout 57014, but also any other failure). The class of the
// real error is therefore unknown; the physical object check is the guard.
export const ABORTED_TRANSACTION_ERROR_LINE =
  'Error: ERROR: current transaction is aborted, commands ignored until end of transaction block';

// True only if exactly one line of the output mentions an error at all, and it is the line above.
export function isOnlyAbortedTransactionError(output: string): boolean {
  const errorLines = output.split(/\r?\n/).filter((line) => /error/i.test(line));
  return errorLines.length === 1 && errorLines[0]!.trimEnd() === ABORTED_TRANSACTION_ERROR_LINE;
}

export type AutoResolveDecision = { resolve: true; name: string } | { resolve: false; message: string };

function seconds(ms: number): number {
  return Math.round(ms / 1000);
}

// Decide whether a failed `migrate deploy` may be followed by `prisma migrate resolve --rolled-back`.
// ALL of these must hold, in this order; the first one that does not hold stops with a fixed message
// (never the URL, never the child's output):
//   1. the child was not killed by the timeout;
//   2. its output is exactly the aborted-transaction error, nothing else mentioning an error;
//   3. it ran at least MIGRATION_AUTO_RESOLVE_MIN_ELAPSED_MS (a faster failure is not a lock wait);
//   4. exactly one unfinished ledger row (no finished_at, no rolled_back_at), so no other failed row;
//   5. its name has a reviewed object list and checksum;
//   6. the row's checksum is that reviewed checksum;
//   7. the ledger has no rolled-back row for that name (at most one auto-resolve per name, ever);
//   8. none of the migration's objects exist (the transaction guarantee really held).
export async function decideAutoResolve(input: {
  child: CapturedChild;
  rows: MigrationRow[];
  reviewed: ReadonlyMap<string, ReviewedMigration>;
  presentObjects: (name: string) => Promise<string[]>;
}): Promise<AutoResolveDecision> {
  const { child, rows, reviewed } = input;
  const stop = (message: string): AutoResolveDecision => ({ resolve: false, message });
  const elapsed = seconds(child.elapsedMs);
  if (child.timedOut) {
    return stop(`migrate deploy was killed after ${elapsed}s; not marking any migration rolled back; read the database state by hand`);
  }
  if (!isOnlyAbortedTransactionError(child.output)) {
    return stop(`migrate deploy failed after ${elapsed}s with an error other than the aborted-transaction error; not marking any migration rolled back`);
  }
  if (child.elapsedMs < MIGRATION_AUTO_RESOLVE_MIN_ELAPSED_MS) {
    return stop(`migrate deploy failed after ${elapsed}s, faster than the ${seconds(MIGRATION_LOCK_TIMEOUT_MS)}s lock timeout, so it is probably not a lock or statement timeout; not marking any migration rolled back; read the failure by hand`);
  }
  const unfinished = rows.filter((row) => !row.finished_at && !row.rolled_back_at);
  if (unfinished.length !== 1) {
    return stop(`${unfinished.length} unfinished migration rows after the failure (expected exactly 1); not marking any migration rolled back`);
  }
  const row = unfinished[0]!;
  const known = reviewed.get(row.migration_name);
  if (!known) {
    return stop(`unfinished migration ${row.migration_name} has no reviewed object list; not marking it rolled back`);
  }
  if (row.checksum !== known.checksum) {
    return stop(`unfinished migration ${row.migration_name} has a checksum that differs from the reviewed one; not marking it rolled back`);
  }
  if (rows.some((other) => other.migration_name === row.migration_name && other.rolled_back_at)) {
    return stop(`migration ${row.migration_name} was already marked rolled back once; not doing it a second time; a human must read the failure`);
  }
  const present = await input.presentObjects(row.migration_name);
  if (present.length > 0) {
    return stop(`${present.length} object(s) of migration ${row.migration_name} exist after the failure; not marking it rolled back`);
  }
  return { resolve: true, name: row.migration_name };
}

// `prisma migrate deploy`, and after a failure the narrow auto-resolve above. Always throws on failure:
// either the fixed stop message, or (after the one allowed `migrate resolve --rolled-back`) the fixed
// "marked rolled back; retry the deploy" message. It never retries the deploy itself.
export async function migrateDeployWithAutoResolve(options: {
  database: QueryClient;
  command: string;
  deployArgs: string[];
  resolveArgs: (name: string) => string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  reviewed: ReadonlyMap<string, ReviewedMigration>;
  timeoutMs?: number;
}): Promise<void> {
  const child = await runCapturedChild(options.command, options.deployArgs, {
    cwd: options.cwd,
    env: options.env,
    timeoutMs: options.timeoutMs ?? MIGRATION_DEPLOY_KILL_TIMEOUT_MS,
  });
  if (child.status === 0 && !child.timedOut) return;

  const rows = await options.database.$queryRawUnsafe<MigrationRow[]>(
    'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations"',
  );
  const decision = await decideAutoResolve({
    child,
    rows,
    reviewed: options.reviewed,
    presentObjects: (name) => listPresentMigrationObjects(options.database, options.reviewed.get(name)!.objects),
  });
  if (!decision.resolve) throw new Error(decision.message);

  const resolved = spawnSync(options.command, options.resolveArgs(decision.name), {
    cwd: options.cwd,
    env: options.env,
    encoding: 'utf8',
    stdio: 'inherit',
  });
  if (resolved.status !== 0) {
    throw new Error(`migrate resolve for ${decision.name} exited with status ${resolved.status ?? 1}; the migration is still marked failed`);
  }
  throw new Error(
    `error class unknown (aborted transaction); migration ${decision.name} marked rolled back; elapsed ${seconds(child.elapsedMs)}s since the migrate started; retry the deploy`,
  );
}

function migrateDeploy(database: QueryClient): Promise<void> {
  return migrateDeployWithAutoResolve({
    database,
    command: process.execPath,
    deployArgs: [prismaBin, 'migrate', 'deploy', '--schema', prismaSchema],
    resolveArgs: (name) => [prismaBin, 'migrate', 'resolve', '--rolled-back', name, '--schema', prismaSchema],
    cwd: repoRoot,
    env: migrationChildEnv(process.env),
    reviewed: reviewedAutoResolvableMigrations(),
  });
}

async function sha256(path: string): Promise<string> {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

async function assertReviewedMigrationFiles() {
  const reviewed = [
    ...tc492AdditiveMigrations,
    [tc488Migration, 'ecf68b38f136da32292c250566d3094d1f8eb0b89c855fd8543adf4544ec7ac6'],
    ...preTc488AdditiveMigrations,
  ] as const;
  for (const [name, expected] of reviewed) {
    const actual = await sha256(join(migrationsDir, name, 'migration.sql'));
    if (actual !== expected) throw new Error(`Reviewed migration checksum mismatch: ${name}`);
  }
}

async function readState(database: ReturnType<typeof createPrismaClient>) {
  const migrations = await database.$queryRawUnsafe<MigrationRow[]>(
    'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations" ORDER BY migration_name',
  );
  const custodyTable = await database.$queryRaw<Array<{ exists: boolean }>>`
    SELECT to_regclass('public.managed_account') IS NOT NULL AS "exists"
  `;
  const migrationDirectories = (await readdir(migrationsDir, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  return {
    migrations,
    migrationDirectories,
    managedAccountTableExists: custodyTable[0]?.exists === true,
  };
}

// A migration can have several history rows (for example a rolled-back attempt
// followed by a finished one). The finished, not-rolled-back row is the one
// that counts.
export function assertMigrationRecorded(rows: MigrationRow[], name: string, checksum: string) {
  const row = rows.find(
    (candidate) => candidate.migration_name === name && candidate.finished_at && !candidate.rolled_back_at,
  );
  if (!row || row.checksum !== checksum) {
    throw new Error(`${name} was not recorded with the reviewed checksum`);
  }
}

async function deployAdditiveMigrationsBeforeTc488(
  database: ReturnType<typeof createPrismaClient>,
  pendingMigrations: string[],
) {
  const { apply: pendingAdditive, park: parkedMigrations } = partitionPreTc488Migrations(pendingMigrations);
  if (pendingAdditive.length > 0) {
    const temporaryRoot = await mkdtemp(join(tmpdir(), 'openkey-pre-tc488-'));
    const movedMigrations: string[] = [];
    try {
      for (const name of parkedMigrations) {
        await rename(join(migrationsDir, name), join(temporaryRoot, name));
        movedMigrations.push(name);
      }
      // Prisma has no single-migration flag. The destructive custody cutover
      // is the only parked entry; the reviewed expand migrations remain visible
      // to the normal engine and are applied in their migration order.
      await migrateDeploy(database);
    } finally {
      for (const name of movedMigrations.reverse()) {
        await rename(join(temporaryRoot, name), join(migrationsDir, name));
      }
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }

  const rows = await database.$queryRawUnsafe<MigrationRow[]>(
    'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations" WHERE migration_name = ANY($1::text[])',
    [...tc492AdditiveMigrations.keys(), ...preTc488AdditiveMigrations.keys()],
  );
  const expected = new Map([...tc492AdditiveMigrations, ...preTc488AdditiveMigrations]);
  for (const [name, checksum] of expected) {
    assertMigrationRecorded(rows, name, checksum);
  }

  const physical = await database.$queryRawUnsafe<Array<{
    user_tinycloud_columns: number;
    canonical_key_column: boolean;
    canonical_key_index: boolean;
    app_preference_columns: number;
    app_preference_client_index: boolean;
    app_preference_status_check: boolean;
    app_preference_client_restrict: boolean;
    control_event_columns: number;
    control_event_index: boolean;
    signing_decision_columns: number;
    signing_decision_user_index: boolean;
    signing_decision_client_index: boolean;
    device_column_count: number;
    user_code_index: boolean;
    rate_index: boolean;
    expiry_index: boolean;
    user_foreign_key: boolean;
    broker_column_count: number;
    broker_expiry_index: boolean;
    broker_primary_key: boolean;
    oauth_client_theme_columns: number;
    request_login_hint_column: boolean;
    request_login_method_column: boolean;
    session_last_email_otp_column: boolean;
    account_provider_identity_index: boolean;
  }>>(`
    SELECT
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'user'
          AND column_name IN ('tinyCloudManageKeyEnabled', 'tinyCloudManageKeyMode', 'tinyCloudManageKeyPolicyEpoch')) AS user_tinycloud_columns,
      (SELECT COUNT(*) = 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'ethereum_keys' AND column_name = 'isCanonicalTinyCloud') AS canonical_key_column,
      to_regclass('public."ethereum_keys_one_active_canonical_tinycloud_key"') IS NOT NULL AS canonical_key_index,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_manage_key_app_preference') AS app_preference_columns,
      to_regclass('public."tinycloud_manage_key_app_preference_clientId_idx"') IS NOT NULL AS app_preference_client_index,
      EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tinycloud_manage_key_app_preference_status_check' AND contype = 'c') AS app_preference_status_check,
      EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tinycloud_manage_key_app_preference_clientId_fkey' AND confdeltype = 'r') AS app_preference_client_restrict,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_manage_key_control_event') AS control_event_columns,
      to_regclass('public."tinycloud_manage_key_control_event_userId_createdAt_idx"') IS NOT NULL AS control_event_index,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_manage_key_signing_decision') AS signing_decision_columns,
      to_regclass('public."tinycloud_manage_key_signing_decision_userId_createdAt_idx"') IS NOT NULL AS signing_decision_user_index,
      to_regclass('public."tinycloud_manage_key_signing_decision_userId_clientId_createdAt_idx"') IS NOT NULL AS signing_decision_client_index,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'device_authorization') AS device_column_count,
      to_regclass('public."device_authorization_userCode_key"') IS NOT NULL AS user_code_index,
      to_regclass('public."device_authorization_requestIpHash_requestedAt_idx"') IS NOT NULL AS rate_index,
      to_regclass('public."device_authorization_status_transactionExpiresAt_idx"') IS NOT NULL AS expiry_index,
      EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'device_authorization_approvedByUserId_fkey'
          AND contype = 'f'
      ) AS user_foreign_key,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'delegation_code') AS broker_column_count,
      to_regclass('public."delegation_code_expiresAt_idx"') IS NOT NULL AS broker_expiry_index,
      EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'delegation_code_pkey' AND contype = 'p'
      ) AS broker_primary_key,
      (SELECT COUNT(*)::int FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'oauth_client'
          AND column_name IN ('themeBackgroundColor', 'themeAccentColor') AND data_type = 'text') AS oauth_client_theme_columns,
      EXISTS (SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_native_request'
          AND column_name = 'loginHint' AND data_type = 'text') AS request_login_hint_column,
      EXISTS (SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'tinycloud_native_request'
          AND column_name = 'loginMethod' AND data_type = 'text') AS request_login_method_column,
      EXISTS (SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'session'
          AND column_name = 'lastEmailOtpAt' AND data_type = 'timestamp without time zone'
          AND is_nullable = 'YES') AS session_last_email_otp_column,
      EXISTS (SELECT 1 FROM pg_index
        WHERE indexrelid = to_regclass('public."account_providerId_accountId_key"')
          AND indisunique AND indisvalid) AS account_provider_identity_index
  `);
  const verified = physical[0];
  if (
    verified?.user_tinycloud_columns !== 3 ||
    !verified.canonical_key_column ||
    !verified.canonical_key_index ||
    verified.app_preference_columns !== 9 ||
    !verified.app_preference_client_index ||
    !verified.app_preference_status_check ||
    !verified.app_preference_client_restrict ||
    verified.control_event_columns !== 8 ||
    !verified.control_event_index ||
    verified.signing_decision_columns !== 8 ||
    !verified.signing_decision_user_index ||
    !verified.signing_decision_client_index ||
    verified?.device_column_count !== 21 ||
    !verified.user_code_index ||
    !verified.rate_index ||
    !verified.expiry_index ||
    !verified.user_foreign_key ||
    verified.broker_column_count !== 4 ||
    !verified.broker_expiry_index ||
    !verified.broker_primary_key ||
    verified.oauth_client_theme_columns !== 2 ||
    !verified.request_login_hint_column ||
    !verified.request_login_method_column ||
    !verified.session_last_email_otp_column ||
    !verified.account_provider_identity_index
  ) {
    throw new Error('Pre-TC-488 additive physical schema verification failed');
  }
  await assertNativeDelegationSchema(database);

  const destructiveRows = await database.$queryRawUnsafe<MigrationRow[]>(
    'SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations" WHERE migration_name = $1',
    tc488Migration,
  );
  if (destructiveRows[0]?.finished_at && !destructiveRows[0].rolled_back_at) {
    throw new Error(`${tc488Migration} was applied while recovering the additive schema`);
  }

  console.log(
    `Production additive migrations verified: ${[...tc492AdditiveMigrations.keys(), ...preTc488AdditiveMigrations.keys()].join(', ')}; ${tc488Migration} remains deliberately pending`,
  );
}

async function main() {
  requirePostgresUrl();
  migrationChildEnv(process.env); // fails fast, before any database access, if the URL cannot carry the lock timeout
  await assertReviewedMigrationFiles();
  const database = createPrismaClient({ connectionString: process.env.DATABASE_URL });
  try {
    const state = await readState(database);
    const mode = selectProductionMigrationMode(state);
    const successful = new Set(
      state.migrations
        .filter((row) => row.finished_at && !row.rolled_back_at)
        .map((row) => row.migration_name),
    );
    const pending = state.migrationDirectories.filter((name) => !successful.has(name));
    if (pending.includes(googleLinkStepUpMigration)) {
      await assertNoDuplicateAccountIdentities(database);
    }
    if (pending.includes(reviewerAccountsMigration)) {
      await assertNoReservedReviewerEmails(database);
    }

    if (mode === 'full') {
      runBunScript('scripts/assert-production-migration-ready.ts');
      await migrateDeploy(database); // the command of db:migrate:apply, run so a hung child is killed and a failure can be read
      runBunScript('db:migrate:verify');
      return;
    }

    await deployAdditiveMigrationsBeforeTc488(database, pending);
  } finally {
    await database.$disconnect();
  }
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
