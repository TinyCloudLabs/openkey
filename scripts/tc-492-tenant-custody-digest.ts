#!/usr/bin/env bun

import { createHash } from 'node:crypto';

import { createPrismaClient } from '../packages/db/src/index';

const removedTables = [
  'eject_revocation_receipt',
  'managed_account_node',
  'possession_event',
  'eject_request',
  'webhook_delivery',
  'webhook_endpoint',
  'managed_account_policy',
  'managed_account_operation',
  'key_custody',
  'managed_account',
  'organization_server_credential',
] as const;

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl?.match(/^postgres(ql)?:\/\//)) throw new Error('DATABASE_URL must be PostgreSQL');

  const prisma = createPrismaClient({ connectionString: databaseUrl });
  try {
    const tables: Record<string, { count: number; sha256: string }> = {};
    const sources: Array<[string, string]> = [
      ['tenantEthereumKeys', `SELECT row_to_json(row_value)::text AS value FROM (
        SELECT * FROM ethereum_keys WHERE "keyPurpose" = 'MANAGED_ACCOUNT' ORDER BY id
      ) row_value`],
      ...removedTables.map((table) => [
        table,
        `SELECT row_to_json(row_value)::text AS value FROM (SELECT * FROM "${table}" ORDER BY id) row_value`,
      ] as [string, string]),
    ];

    for (const [name, query] of sources) {
      const rows = await prisma.$queryRawUnsafe<Array<{ value: string }>>(query);
      const digest = createHash('sha256');
      for (const row of rows) digest.update(row.value).update('\n');
      tables[name] = { count: rows.length, sha256: digest.digest('hex') };
    }
    const aggregate = createHash('sha256').update(JSON.stringify(tables)).digest('hex');
    console.log(JSON.stringify({ schema: 'openkey.tc492.tenant-custody.v1', aggregateSha256: aggregate, tables }));
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
