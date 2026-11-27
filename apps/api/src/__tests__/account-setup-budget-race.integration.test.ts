import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import type { PrismaClient } from '@openkey/db';
import {
  ACCOUNT_SETUP_BUDGET_LIMITS, ACCOUNT_SETUP_BUDGET_SESSION_LIMIT, refundAccountSetupBudget, spendAccountSetupBudget,
} from '../services/account-setup-budget';

// The account setup budgets hold their limits when many calls arrive at the same moment: N parallel spends racing
// for the last units of a limit let exactly that many through and refuse the rest. The spend reads a counter and
// writes it back, so only the lock on the user row keeps two calls from reading the same count; the test fails when
// that lock is removed. It needs separate connections to a real server, which PGlite (one connection, calls run one
// after another) cannot show, so the Postgres run uses OPENKEY_TEST_POSTGRES_URL as the other race tests do and
// creates and drops its own database. The PGlite run checks the same counts.
const backend = process.env.BUDGET_RACE_TEST_CHILD;
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '../../../..');

if (!backend) {
  for (const engine of ['pglite', 'postgres']) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(
      `account setup budget race (${engine})`,
      async () => {
        const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
          cwd: root,
          env: { ...process.env, BUDGET_RACE_TEST_CHILD: engine, NODE_ENV: 'test', TEE_MODE: 'development' },
          stdout: 'pipe',
          stderr: 'pipe',
        });
        const [stdout, stderr, exitCode] = await Promise.all([
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
          child.exited,
        ]);
        expect(exitCode, stdout + stderr).toBe(0);
      },
      300_000,
    );
  }
} else {
  const directory = await mkdtemp(join(tmpdir(), 'openkey-budget-race-'));
  const databaseName = `budget_race_${randomUUID().replaceAll('-', '')}`;
  let admin: Client | undefined;
  let prisma: PrismaClient;
  let userId: string;

  const parallel = <T>(count: number, run: (index: number) => Promise<T>) => Promise.all(Array.from({ length: count }, (_, index) => run(index)));
  const used = async (identifier: string) => Number((await prisma.verification.findFirst({ where: { identifier } }))?.value ?? 'none');

  beforeAll(async () => {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    let connectionString: string;
    if (backend === 'postgres') {
      if (!postgresUrl) throw new Error('OPENKEY_TEST_POSTGRES_URL is required for PostgreSQL coverage');
      // Never migrate the supplied database; all data lives in a disposable one.
      admin = new Client({ connectionString: postgresUrl });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${databaseName}"`);
      const target = new URL(postgresUrl);
      target.pathname = `/${databaseName}`;
      connectionString = target.toString();
      const migrationConnection = new Client({ connectionString });
      await migrationConnection.connect();
      try {
        for (const migration of migrations) {
          await migrationConnection.query(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
        }
      } finally {
        await migrationConnection.end();
      }
    } else {
      const database = new PGlite(directory);
      try {
        for (const migration of migrations) {
          await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
        }
      } finally {
        await database.close();
      }
      connectionString = `pglite:${directory}`;
    }
    process.env.DATABASE_URL = connectionString;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await admin.end();
    }
    await rm(directory, { recursive: true, force: true });
  });

  beforeEach(async () => {
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE "user", "verification" CASCADE`);
    userId = randomUUID();
    await prisma.user.create({ data: { id: userId, email: `${userId}@example.test`, name: 'Racer', emailVerified: true } });
  });

  describe.each(['send', 'verify'] as const)('the %s budget under parallel spends', (budget) => {
    const userLimit = ACCOUNT_SETUP_BUDGET_LIMITS[budget];

    test('parallel spends racing for the last units of the user limit let exactly the limit through', async () => {
      // Seven units are spent one by one, from sessions that each stay under their share.
      for (let spent = 0; spent < 7; spent += 1) {
        expect(await spendAccountSetupBudget(prisma, userId, budget, `early-${Math.floor(spent / 2)}`)).toBe(true);
      }
      const results = await parallel(16, (index) => spendAccountSetupBudget(prisma, userId, budget, `racer-${index}`));
      expect(results.filter(Boolean)).toHaveLength(userLimit - 7);
      expect(results.filter((result) => !result)).toHaveLength(16 - (userLimit - 7));
      expect(await used(`account-setup-budget:${budget}:${userId}`)).toBe(userLimit);
    });

    test('parallel spends of one session let exactly its share through', async () => {
      const results = await parallel(16, () => spendAccountSetupBudget(prisma, userId, budget, 'one-session'));
      expect(results.filter(Boolean)).toHaveLength(ACCOUNT_SETUP_BUDGET_SESSION_LIMIT);
      expect(await used(`account-setup-budget:${budget}:${userId}`)).toBe(ACCOUNT_SETUP_BUDGET_SESSION_LIMIT);
      expect(await used(`account-setup-budget:${budget}:${userId}:one-session`)).toBe(ACCOUNT_SETUP_BUDGET_SESSION_LIMIT);
    });

    test('parallel spends that open the window count each unit once', async () => {
      const results = await parallel(16, (index) => spendAccountSetupBudget(prisma, userId, budget, `fresh-${index}`));
      expect(results.filter(Boolean)).toHaveLength(userLimit);
      expect(await prisma.verification.count({ where: { identifier: `account-setup-budget:${budget}:${userId}` } })).toBe(1);
    });

    test('parallel refunds never take a count below zero', async () => {
      for (let spent = 0; spent < 3; spent += 1) await spendAccountSetupBudget(prisma, userId, budget, 'refunder');
      await parallel(8, () => refundAccountSetupBudget(prisma, userId, budget, 'refunder'));
      expect(await used(`account-setup-budget:${budget}:${userId}`)).toBe(0);
      expect(await used(`account-setup-budget:${budget}:${userId}:refunder`)).toBe(0);
    });
  });
}
