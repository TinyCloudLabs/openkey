#!/usr/bin/env bun
/**
 * Read-only production diagnostic for TinyCloud bootstrap failures.
 *
 * DATABASE_URL is supplied by GitHub Actions. Output deliberately excludes
 * user, key, address, and signing-decision identifiers.
 */

import { createPrismaClient } from '../packages/db/src/index';

export function sanitizeFailureReason(value: string | null): string | null {
  if (!value) return null;
  return value
    .replace(/0x[a-fA-F0-9]{40}/g, '[address]')
    .replace(/did:pkh:[^\s"'`,)]+/g, '[did]')
    .replace(/(?:authorization|bearer)\s*[:=]?\s*[^\s"',}]+/gi, '[authorization]')
    .slice(0, 1_000);
}

async function main() {
  if (process.env.CONFIRM_INSPECT !== 'INSPECT_TINYCLOUD_BOOTSTRAP') {
    throw new Error('CONFIRM_INSPECT must equal INSPECT_TINYCLOUD_BOOTSTRAP');
  }
  if (!process.env.DATABASE_URL?.trim()) {
    throw new Error('DATABASE_URL is required');
  }

  const prisma = createPrismaClient();
  try {
    const states = await prisma.tinyCloudBootstrapState.findMany({
      orderBy: { checkedAt: 'desc' },
      take: 5,
      select: {
        status: true,
        tinycloudHost: true,
        failureCode: true,
        failureReason: true,
        checkedAt: true,
        completedAt: true,
      },
    });
    console.log(JSON.stringify(states.map((state) => ({
      status: state.status,
      tinycloudHost: state.tinycloudHost,
      failureCode: state.failureCode,
      failureReason: sanitizeFailureReason(state.failureReason),
      checkedAt: state.checkedAt.toISOString(),
      completedAt: state.completedAt?.toISOString() ?? null,
    })), null, 2));
  } finally {
    await prisma.$disconnect();
  }
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(`Inspection failed: ${error instanceof Error ? error.message : 'unknown error'}`);
    process.exit(1);
  });
}
