// Prints how many renewal leases are live (TC-3088). Read-only and counts only.
//
//   DATABASE_URL=<read-only production url> bun run scripts/renewal-leases-report.ts
//
// It cannot stop anything: revoking a lease needs OpenKey's sealed keys, which only the API holds. To stop every
// live lease an OpenKey-held key signed, set OPENKEY_RENEWAL_LEASES=stop and redeploy the API (docs/deployment.md),
// then run this again: `openkeySigned` and `unconfirmed` fall to 0; `walletSigned` stays until each wallet revokes.
import { createPrismaClient } from '../packages/db/src/index';
import { renewalLeaseReport } from '../apps/api/src/services/renewal-lease-report';

async function main() {
  if (!process.env.DATABASE_URL?.match(/^postgres(ql)?:\/\//)) throw new Error('DATABASE_URL must be a PostgreSQL url');
  const database = createPrismaClient();
  try {
    // A read-only transaction: the connection refuses writes even if the query were wrong.
    const report = await database.$transaction(async (tx) => {
      await tx.$executeRawUnsafe('SET TRANSACTION READ ONLY');
      return renewalLeaseReport(tx as unknown as Parameters<typeof renewalLeaseReport>[0]);
    });
    console.log(JSON.stringify({ at: new Date().toISOString(), ...report }, null, 2));
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
