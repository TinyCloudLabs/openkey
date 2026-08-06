#!/usr/bin/env bun

import { createHash } from 'node:crypto';

import { createPrismaClient } from '../packages/db/src/index';

const queries = {
  oauthClients: `
    SELECT jsonb_build_object(
      'id', id, 'clientId', "clientId", 'clientSecret', "clientSecret", 'name', name,
      'uri', uri, 'icon', icon, 'redirectUris', "redirectUris", 'scopes', scopes,
      'tinycloudSessionPolicy', "tinycloudSessionPolicy", 'tinycloudSessionOrigin', "tinycloudSessionOrigin",
      'disabled', disabled, 'skipConsent', "skipConsent", 'enableEndSession', "enableEndSession",
      'tokenEndpointAuthMethod', "tokenEndpointAuthMethod", 'grantTypes', "grantTypes",
      'responseTypes', "responseTypes", 'type', type, 'public', public, 'contacts', contacts,
      'tos', tos, 'policy', policy, 'softwareId', "softwareId", 'softwareVersion', "softwareVersion",
      'softwareStatement', "softwareStatement", 'userId', "userId", 'referenceId', "referenceId",
      'organizationId', "organizationId", 'metadata', COALESCE(metadata, '{}'::jsonb) - 'openkeyClientMode' - 'openkeyOrganizationId',
      'createdAt', "createdAt", 'updatedAt', "updatedAt"
    )::text AS value FROM oauth_client ORDER BY id`,
  oauthConsents: `
    SELECT jsonb_build_object(
      'id', id, 'userId', "userId", 'clientId', "clientId", 'referenceId', "referenceId",
      'scopes', scopes, 'createdAt', "createdAt", 'updatedAt', "updatedAt"
    )::text AS value FROM oauth_consent ORDER BY id`,
  developerAccounts: `
    SELECT jsonb_build_object(
      'id', id, 'userId', "userId", 'stripeCustomerId', "stripeCustomerId", 'plan', plan,
      'billingState', "billingState", 'mauLimit', "mauLimit", 'appLimit', "appLimit",
      'stripeSubscriptionId', "stripeSubscriptionId", 'organizationId', "organizationId",
      'createdAt', "createdAt", 'updatedAt', "updatedAt"
    )::text AS value FROM developer_account ORDER BY id`,
  organizations: `
    SELECT jsonb_build_object(
      'id', id, 'name', name, 'plan', plan, 'billingState', "billingState",
      'stripeCustomerId', "stripeCustomerId", 'stripeSubscriptionId', "stripeSubscriptionId",
      'createdAt', "createdAt", 'updatedAt', "updatedAt"
    )::text AS value FROM organization ORDER BY id`,
  organizationMemberships: `
    SELECT jsonb_build_object(
      'id', id, 'organizationId', "organizationId", 'userId', "userId", 'role', role,
      'status', status, 'validFrom', "validFrom", 'validUntil', "validUntil",
      'revokedAt', "revokedAt", 'createdAt', "createdAt"
    )::text AS value FROM organization_membership ORDER BY id`,
  planEntitlements: `
    SELECT jsonb_build_object(
      'id', id, 'organizationId', "organizationId", 'version', version, 'maxApps', "maxApps",
      'maxOrganizationMembers', "maxOrganizationMembers", 'requestsPerMinute', "requestsPerMinute",
      'auditRetentionDays', "auditRetentionDays", 'createdAt', "createdAt", 'updatedAt', "updatedAt"
    )::text AS value FROM plan_entitlements ORDER BY id`,
} as const;

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl?.match(/^postgres(ql)?:\/\//)) throw new Error('DATABASE_URL must be PostgreSQL');

  const prisma = createPrismaClient({ connectionString: databaseUrl });
  try {
    const tables: Record<string, { count: number; sha256: string }> = {};
    for (const [name, query] of Object.entries(queries)) {
      const rows = await prisma.$queryRawUnsafe<Array<{ value: string }>>(query);
      const digest = createHash('sha256');
      for (const row of rows) digest.update(row.value).update('\n');
      tables[name] = { count: rows.length, sha256: digest.digest('hex') };
    }
    const aggregate = createHash('sha256').update(JSON.stringify(tables)).digest('hex');
    console.log(JSON.stringify({ schema: 'openkey.tc492.preservation.v1', aggregateSha256: aggregate, tables }));
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
