import { expect, test } from 'bun:test';
import { mockModules } from './mock-module';
import { SCOREBOARD_EXCLUSION_CRITERIA } from '../services/scoreboard-exclusions';

await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({}) }),
});

test('internal metrics expose aggregate manage-key health without identity material', async () => {
  const userCounts = [10, 2, 8, 1];
  const keyCounts = [12, 10, 3, 8];
  const decisionCounts = [7, 5, 2];
  const preferenceCounts = [4, 3];
  const database = {
    user: { count: async () => userCounts.shift() },
    ethereumKey: { count: async () => keyCounts.shift() },
    tinyCloudManageKeySigningDecision: { count: async () => decisionCounts.shift() },
    tinyCloudManageKeyAppPreference: { count: async () => preferenceCounts.shift() },
  };
  const { collectInternalMetrics } = await import('../routes/internal-metrics?tc492-metrics' as string);
  const result = await collectInternalMetrics(
    database as unknown as Parameters<typeof collectInternalMetrics>[0],
    new Date('2026-08-05T21:00:00.000Z'),
  );
  expect(result.accounts).toMatchObject({ real: 10, excluded: 0 });
  expect(result).toEqual({
    generatedAt: '2026-08-05T21:00:00.000Z',
    accounts: { total: 10, new24h: 2, real: 10, excluded: 0, exclusionCriteria: SCOREBOARD_EXCLUSION_CRITERIA },
    keys: { total: 12, active: 10, new24h: 3 },
    tinyCloudManageKey: {
      canonicalResolution: { eligibleUsers: 8, canonicalKeys: 8, missingCanonicalUsers: 1 },
      appGrants: { enabled: 4, disabled: 3 },
      signingDecisions24h: { total: 7, allowed: 5, denied: 2 },
    },
  });
  const serialized = JSON.stringify(result);
  for (const forbidden of ['userId', 'keyId', 'address', 'token', 'message', 'signature']) {
    expect(serialized).not.toContain(forbidden);
  }
});
