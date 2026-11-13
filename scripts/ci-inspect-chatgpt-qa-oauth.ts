#!/usr/bin/env bun
/** Temporary release diagnostic. Never merge; only the synthetic QA subject and client are selectable. */
import { createPrismaClient, type PrismaClient } from '../packages/db/src/index';

const QA_ADDRESS = '0xaaffff99d4159af8167d514dbd0adb8c2f6f1bba';
const QA_CLIENT_ID = 'vAiqAgVOQIAkHfmGqkToBDsPTWCbxfso';

export async function inspectQaOAuthTiming(prisma: PrismaClient) {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SET TRANSACTION READ ONLY`;
    await tx.$executeRaw`SET LOCAL statement_timeout = '5s'`;
    await tx.$executeRaw`SET LOCAL TIME ZONE 'UTC'`;
    const [observation] = await tx.$queryRaw<Array<{ observedAt: Date; readOnly: string }>>`
      SELECT transaction_timestamp() AS "observedAt",
             current_setting('transaction_read_only') AS "readOnly"`;
    if (observation.readOnly !== 'on') throw new Error('READ_ONLY_REQUIRED');
    const subjects = await tx.$queryRaw<Array<{ id: string }>>`
      SELECT DISTINCT u.id FROM "user" u
      JOIN ethereum_keys k ON k."userId" = u.id
      WHERE lower(k.address) = ${QA_ADDRESS} LIMIT 2`;
    if (subjects.length !== 1) throw new Error('EXACT_QA_SUBJECT_REQUIRED');
    const subjectId = subjects[0].id;
    const refresh = await tx.$queryRaw<Array<Record<string, unknown>>>`
      SELECT md5(r.id) AS "metadataCorrelation", r."createdAt" AS "issuedAt",
             r."expiresAt" AS "refreshExpiresAt", r.revoked AS "revokedAt",
             r."authTime" AS "authTime", md5(r."sessionId") AS "sessionCorrelation", r.scopes
      FROM oauth_refresh_token r
      WHERE r."userId" = ${subjectId} AND r."clientId" = ${QA_CLIENT_ID}
        AND 'tinycloud:mcp' = ANY(r.scopes)
      ORDER BY r."createdAt", r.id LIMIT 100`;
    const opaqueAccess = await tx.$queryRaw<Array<Record<string, unknown>>>`
      SELECT md5(a.id) AS "metadataCorrelation", a."createdAt" AS "issuedAt",
             a."expiresAt" AS "accessExpiresAt", md5(a."refreshId") AS "refreshCorrelation",
             md5(a."sessionId") AS "sessionCorrelation", a.scopes
      FROM oauth_access_token a
      WHERE a."userId" = ${subjectId} AND a."clientId" = ${QA_CLIENT_ID}
        AND 'tinycloud:mcp' = ANY(a.scopes)
      ORDER BY a."createdAt", a.id LIMIT 100`;
    if (refresh.length === 0) throw new Error('QA_REFRESH_METADATA_REQUIRED');
    if (refresh.length === 100 || opaqueAccess.length === 100) throw new Error('ROW_LIMIT_REACHED');
    return {
      ...observation,
      clientId: QA_CLIENT_ID,
      refresh,
      opaqueAccess,
      limits: 'No token values, user identifiers, email, addresses, session IDs, or signing context are selected for output. JWT access-token expiry is not observed by this query.',
    };
  }, { maxWait: 5_000, timeout: 15_000 });
}

async function main() {
  if (process.env.CONFIRM_INSPECT !== 'INSPECT_CHATGPT_QA_OAUTH') throw new Error('CONFIRMATION_REQUIRED');
  if (!/^postgres(?:ql)?:\/\//.test(process.env.DATABASE_URL ?? '')) throw new Error('POSTGRES_REQUIRED');
  const prisma = createPrismaClient();
  try {
    console.log(JSON.stringify(await inspectQaOAuthTiming(prisma), null, 2));
  } finally {
    await prisma.$disconnect();
  }
}

if (import.meta.main) {
  main().catch((error) => {
    const code = error instanceof Error && /^[A-Z_]+$/.test(error.message) ? error.message : 'DATABASE_INSPECTION_FAILED';
    console.error(`QA OAuth metadata inspection failed: ${code}`);
    process.exitCode = 1;
  });
}
