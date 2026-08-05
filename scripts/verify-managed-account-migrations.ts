import { createPrismaClient } from '@openkey/db';

const forbiddenRelations = [
  'managed_account', 'managed_account_operation', 'managed_account_policy',
  'managed_account_node', 'eject_request', 'eject_revocation_receipt',
  'key_custody', 'possession_event', 'webhook_endpoint', 'webhook_delivery',
  'organization_server_credential',
];
const forbiddenTypes = [
  'ManagedAccountState', 'CustodianType', 'RevocationStatus', 'NodeRole',
  'RevocationReceiptStatus', 'EjectRequestStatus', 'OrganizationCredentialKind',
  'OauthClientMode',
];

async function main() {
  const prisma = createPrismaClient();
  try {
    const relations = await prisma.$queryRaw<Array<{ name: string }>>`
      SELECT c.relname AS name FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname = ANY(${forbiddenRelations})
    `;
    const types = await prisma.$queryRaw<Array<{ name: string }>>`
      SELECT t.typname AS name FROM pg_type t
      JOIN pg_namespace n ON n.oid = t.typnamespace
      WHERE n.nspname = 'public' AND t.typname = ANY(${forbiddenTypes})
    `;
    if (relations.length || types.length) {
      throw new Error(`TC-488 cutover is incomplete: relations=${relations.map((row) => row.name).join(',')} types=${types.map((row) => row.name).join(',')}`);
    }
    console.log('Verified TC-488 organization custody cutover: no deleted relations or enum types remain.');
  } finally {
    await prisma.$disconnect();
  }
}

await main();
