import { test, expect } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createPrismaClient } from '@openkey/db';
import { recordDeletionPreflight, recordDeletionReviewDecision } from './account-deletion-review-ledger';

test('dependency review atomically locks access, retains keys and survives restart with decision audit', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc2871-review-'));
  const database = new PGlite(dir);
  const migrations = resolve(import.meta.dir, '../../../../packages/db/prisma/migrations');
  try {
    for (const name of (await readdir(migrations)).sort()) {
      if (name !== 'migration_lock.toml') await database.exec(await readFile(join(migrations, name, 'migration.sql'), 'utf8'));
    }
  } finally { await database.close(); }
  const connect = () => createPrismaClient({ connectionString: `pglite:${dir}` });
  let db = connect();
  try {
    await db.user.create({ data: { id: 'review-owner', email: 'review@example.test' } });
    await db.ethereumKey.create({ data: { id: 'review-key', userId: 'review-owner', address: 'synthetic-review', publicKey: 'synthetic', sealedBlob: 'synthetic' } });
    await db.session.create({ data: { id: 'review-session', userId: 'review-owner', token: 'synthetic', expiresAt: new Date(Date.now() + 60_000) } });
    await db.accountDeletionJob.create({ data: { id: 'review-job', userId: 'review-owner', state: 'preflight_pending', progress: {} } });
    await db.$transaction(tx => recordDeletionPreflight(tx, 'review-job', 'review-owner', {
      state: 'pending_review', resources: { host: ['private-network-name'] }, inventoryComplete: { host: true },
      dependencies: { host: { count: 1, hashes: ['a'.repeat(64)] } }, unavailableHosts: [],
    }));
    expect(await db.session.count()).toBe(0);
    expect(await db.ethereumKey.count()).toBe(1);
    expect((await db.user.findUniqueOrThrow({ where: { id: 'review-owner' } })).lockedAt).not.toBeNull();
    expect((await db.accountDeletionJob.findUniqueOrThrow({ where: { id: 'review-job' } })).state).toBe('pending_review');
    await db.$transaction(tx => recordDeletionReviewDecision(tx, 'review-job', { actor: 'Naomi', at: new Date(), reason: 'Wait for recipient re-encryption', disposition: 'wait_for_re-encryption' }));
    await db.$disconnect();
    db = connect();
    const records = await db.accountDeletionReview.findMany({ where: { jobId: 'review-job' }, orderBy: { createdAt: 'asc' } });
    expect(records).toHaveLength(2);
    expect(records[1]?.disposition).toBe('wait_for_re-encryption');
    expect(JSON.stringify(records)).not.toContain('private-network-name');
    expect(await db.ethereumKey.count()).toBe(1);
  } finally { await db.$disconnect(); await rm(dir, { recursive: true, force: true }); }
}, 90_000);
