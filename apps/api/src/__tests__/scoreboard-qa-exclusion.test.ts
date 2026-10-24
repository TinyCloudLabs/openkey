import { expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { ScoreboardDatabase } from '../routes/scoreboard-metrics';

// The scoreboard queries run against a real Postgres engine (PGlite) with the
// tracked migrations, in a separate process so module mocks used by other API
// tests cannot hide SQL errors such as a wrong table name.
const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_SCOREBOARD_QA_TEST_CHILD !== '1') {
  test('scoreboard QA exclusion runs against the real schema', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_SCOREBOARD_QA_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        OPENKEY_METRICS_READ_TOKEN: 'read-token',
        TEST_ACCOUNT_REGISTRY_JSON: JSON.stringify({
          userIds: [],
          clientIds: [],
          emailDomains: ['example.test'],
          patterns: [{ regex: '^fixture-qa-[a-z0-9]+@example\\.test$', qaEligible: true }],
        }),
      },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    expect(exitCode, stdout + stderr).toBe(0);
  }, 120_000);
} else {
  const directory = await mkdtemp(join(tmpdir(), 'openkey-scoreboard-qa-'));
  const pglite = new PGlite(directory);
  try {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const migration of migrations) {
      await pglite.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    }
  } finally {
    await pglite.close();
  }
  process.env.DATABASE_URL = `pglite:${directory}`;
  delete process.env.OPENKEY_DATABASE_SCHEMA;

  const { createPrismaClient } = await import('@openkey/db');
  const prisma = createPrismaClient();
  const { qaAccountIds, scoreboardMetricsRouter } = await import('../routes/scoreboard-metrics');
  const { loadTestAccountRegistry } = await import('../services/qa-registration');

  const today = new Date(new Date().toISOString().slice(0, 10));
  const users = [
    { id: 'qa-probe', email: 'fixture-qa-7f3a@example.test' },
    { id: 'real-user', email: 'someone@example.test' },
    { id: 'lookalike-domain', email: 'fixture-qa-7f3a@example.com' },
    { id: 'pattern-miss', email: 'fixture-qaabc@example.test' },
  ];

  test('seed users and sign-ins', async () => {
    for (const user of users) {
      await prisma.user.create({ data: { id: user.id, email: user.email, name: user.id, emailVerified: true } });
      await prisma.appSignInDay.create({ data: { userId: user.id, origin: 'https://openkey.test', day: today } });
    }
    expect(await prisma.user.count()).toBe(users.length);
  });

  test('qaAccountIds reads the mapped user table and returns only QA-eligible accounts', async () => {
    const registry = loadTestAccountRegistry().registry;
    expect(registry.emailDomains).toEqual(['example.test']);
    const ids = await qaAccountIds(prisma as unknown as ScoreboardDatabase, registry);
    expect(ids).toEqual(['qa-probe']);
  });

  test('no registry domains means no QA exclusions, whatever the patterns', async () => {
    const { qaEligiblePatterns } = loadTestAccountRegistry().registry;
    expect(qaEligiblePatterns.length).toBe(1);
    expect(await qaAccountIds(prisma as unknown as ScoreboardDatabase, { emailDomains: [], qaEligiblePatterns })).toEqual([]);
  });

  test('/app-users answers 200 and excludes the QA-eligible account', async () => {
    const res = await scoreboardMetricsRouter.request('/app-users', { headers: { Authorization: 'Bearer read-token' } });
    expect(res.status).toBe(200);
    // real-user, lookalike-domain and pattern-miss remain; the QA-eligible account is excluded.
    expect(await res.json()).toEqual({ total: 3, active7d: 3 });
  });

  test('cleanup', async () => {
    await prisma.$disconnect();
    await rm(directory, { recursive: true, force: true });
  });
}
