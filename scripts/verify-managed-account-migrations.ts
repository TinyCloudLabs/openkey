#!/usr/bin/env bun

import { createPrismaClient } from '../packages/db/src/index';

const requiredMigrations = [
  '20260715_0001_managed_accounts_phase_a_fix',
  '20260715_0002_managed_accounts_registration_api',
  '20260715_0003_managed_accounts_eject_api',
  '20260715_0004_managed_accounts_webhooks',
] as const;

const requiredTriggers = [
  [
    'eject_request_guard',
    'eject_request',
    'openkey_eject_request_guard',
    false,
  ],
  [
    'ethereum_keys_classification_guard',
    'ethereum_keys',
    'openkey_immutable_key_classification',
    false,
  ],
  [
    'key_custody_custody_commit_guard',
    'key_custody',
    'openkey_key_custody_commit_guard',
    true,
  ],
  [
    'key_custody_history_guard',
    'key_custody',
    'openkey_custody_history_guard',
    false,
  ],
  [
    'key_custody_insert_guard',
    'key_custody',
    'openkey_custody_insert_guard',
    false,
  ],
  [
    'managed_account_custody_commit_guard',
    'managed_account',
    'openkey_managed_account_custody_commit_guard',
    true,
  ],
  [
    'managed_account_epoch_guard',
    'managed_account',
    'openkey_custody_epoch_guard',
    false,
  ],
  [
    'managed_account_identity_guard',
    'managed_account',
    'openkey_managed_account_identity_guard',
    false,
  ],
  [
    'managed_account_key_guard',
    'managed_account',
    'openkey_managed_key_guard',
    false,
  ],
  [
    'managed_account_state_guard',
    'managed_account',
    'openkey_managed_account_state_guard',
    false,
  ],
  [
    'membership_delete_guard',
    'organization_membership',
    'openkey_append_only_history_guard',
    false,
  ],
  [
    'membership_identity_guard',
    'organization_membership',
    'openkey_membership_identity_guard',
    false,
  ],
  [
    'possession_event_append_only',
    'possession_event',
    'openkey_possession_event_guard',
    false,
  ],
  [
    'possession_event_custody_commit_guard',
    'possession_event',
    'openkey_possession_event_commit_guard',
    true,
  ],
  [
    'registration_intent_tenant_guard',
    'registration_intent',
    'openkey_registration_intent_tenant_guard',
    false,
  ],
  [
    'webhook_delivery_tenant_guard',
    'webhook_delivery',
    'openkey_webhook_tenant_guard',
    false,
  ],
] as const;

const requiredCheckConstraints = [
  [
    'ethereum_keys_sealing_context_format_check',
    'ethereum_keys',
    `CHECK ("sealingContext" IS NULL OR "sealingContext" ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'::text)`,
  ],
  ['key_custody_epoch_positive_check', 'key_custody', 'CHECK (epoch > 0)'],
  [
    'managed_account_epoch_positive_check',
    'managed_account',
    'CHECK ("custodyEpoch" >= 0)',
  ],
  [
    'organization_membership_interval_check',
    'organization_membership',
    'CHECK ("validUntil" IS NULL OR "validFrom" < "validUntil")',
  ],
  [
    'organization_membership_status_check',
    'organization_membership',
    `CHECK (status = 'ACTIVE'::"MembershipStatus" AND "revokedAt" IS NULL OR status = 'REVOKED'::"MembershipStatus" AND "revokedAt" IS NOT NULL)`,
  ],
  [
    'possession_event_signature_check',
    'possession_event',
    'CHECK (length(TRIM(BOTH FROM "accountKeySignature")) > 0)',
  ],
] as const;

type TriggerRow = {
  name: string;
  relation: string;
  function: string;
  enabled: string;
  deferrable: boolean;
  initiallyDeferred: boolean;
};

type ConstraintRow = {
  name: string;
  relation: string;
  definition: string;
  validated: boolean;
};

function normalizeDefinition(definition: string) {
  return definition.replace(/\s+/g, ' ').trim();
}

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error('DATABASE_URL must be set');
  }
  if (
    !databaseUrl.startsWith('postgresql://') &&
    !databaseUrl.startsWith('postgres://')
  ) {
    throw new Error('Migration verification requires PostgreSQL');
  }

  const prisma = createPrismaClient({ connectionString: databaseUrl });
  try {
    const migrations = await prisma.$queryRawUnsafe<
      Array<{
        migration_name: string;
        finished_at: Date | null;
        rolled_back_at: Date | null;
      }>
    >(
      'SELECT migration_name, finished_at, rolled_back_at FROM "_prisma_migrations"'
    );
    const successfulMigrations = new Set(
      migrations
        .filter((row) => row.finished_at && !row.rolled_back_at)
        .map((row) => row.migration_name)
    );

    const triggers = await prisma.$queryRaw<Array<TriggerRow>>`
      SELECT
        t.tgname AS name,
        r.relname AS relation,
        p.proname AS function,
        t.tgenabled::text AS enabled,
        t.tgdeferrable AS deferrable,
        t.tginitdeferred AS "initiallyDeferred"
      FROM pg_trigger t
      JOIN pg_class r ON r.oid = t.tgrelid
      JOIN pg_namespace n ON n.oid = r.relnamespace
      JOIN pg_proc p ON p.oid = t.tgfoid
      WHERE n.nspname = 'public' AND NOT t.tgisinternal
    `;
    const constraints = await prisma.$queryRaw<Array<ConstraintRow>>`
      SELECT
        c.conname AS name,
        r.relname AS relation,
        pg_get_constraintdef(c.oid, true) AS definition,
        c.convalidated AS validated
      FROM pg_constraint c
      JOIN pg_class r ON r.oid = c.conrelid
      JOIN pg_namespace n ON n.oid = r.relnamespace
      WHERE n.nspname = 'public' AND c.contype = 'c'
    `;

    const failures: string[] = [];
    for (const migration of requiredMigrations) {
      if (!successfulMigrations.has(migration)) {
        failures.push(`Missing successfully applied migration: ${migration}`);
      }
    }

    for (const [name, relation, functionName, deferred] of requiredTriggers) {
      const row = triggers.find((candidate) => candidate.name === name);
      if (!row) {
        failures.push(`Missing security trigger: ${name}`);
        continue;
      }
      if (
        row.relation !== relation ||
        row.function !== functionName ||
        row.enabled !== 'O' ||
        row.deferrable !== deferred ||
        row.initiallyDeferred !== deferred
      ) {
        failures.push(
          `Invalid security trigger ${name}: expected relation=${relation}, function=${functionName}, enabled=O, deferrable=${deferred}, initiallyDeferred=${deferred}; got relation=${row.relation}, function=${row.function}, enabled=${row.enabled}, deferrable=${row.deferrable}, initiallyDeferred=${row.initiallyDeferred}`
        );
      }
    }

    for (const [name, relation, definition] of requiredCheckConstraints) {
      const row = constraints.find((candidate) => candidate.name === name);
      if (!row) {
        failures.push(`Missing check constraint: ${name}`);
        continue;
      }
      if (
        row.relation !== relation ||
        !row.validated ||
        normalizeDefinition(row.definition) !== normalizeDefinition(definition)
      ) {
        failures.push(
          `Invalid check constraint ${name}: expected relation=${relation}, validated=true, definition=${normalizeDefinition(
            definition
          )}; got relation=${row.relation}, validated=${
            row.validated
          }, definition=${normalizeDefinition(row.definition)}`
        );
      }
    }

    if (failures.length > 0) {
      throw new Error(failures.join('\n'));
    }
  } finally {
    await prisma.$disconnect();
  }

  console.log(
    `Verified ${requiredMigrations.length} managed-account migrations, ${requiredTriggers.length} exact security trigger attachments, and ${requiredCheckConstraints.length} exact check constraints.`
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
