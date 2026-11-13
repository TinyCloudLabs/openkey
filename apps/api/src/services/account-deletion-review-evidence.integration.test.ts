import type { DurableResourceCompletion } from './account-deletion-review-completions';
import { test, expect } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createPrismaClient } from '@openkey/db';
import { buildReviewSnapshot, type ResourceDependencyObservation } from './account-deletion-decision';
import { sweepAccountDeletions } from './account-deletion-sweep';
import type { DeletionReviewRuntime } from './account-deletion-review-worker';
const origin = 'https://node.example.test';
const hosts = { configured: [{ hostId: 'node-test', url: origin }], recorded: [origin], uncertain: false };
const resource = 'urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';

test('partial zero stays pending, each zero attempt is immutable, and stale workers cannot append a resolution', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc2871-review-evidence-'));
  const database = new PGlite(dir);
  const migrations = resolve(import.meta.dir, '../../../../packages/db/prisma/migrations');
  try { for (const name of (await readdir(migrations)).sort()) if (name !== 'migration_lock.toml') await database.exec(await readFile(join(migrations, name, 'migration.sql'), 'utf8')); }
  finally { await database.close(); }
  const db = createPrismaClient({ connectionString: `pglite:${dir}` });
  try {
    const createJob = async (id: string) => {
      await db.user.create({ data: { id, email: `${id}@example.test` } });
      await db.ethereumKey.create({ data: { id, userId: id, address: `synthetic-${id}`, publicKey: 'synthetic', sealedBlob: 'synthetic' } });
      return db.accountDeletionJob.create({ data: { userId: id, state: 'pending_review', progress: { hostSnapshot: hosts, reviewTargets: { [origin]: [resource] } } } });
    };
    let fingerprint = 'c';
    const check = async () => {
      const observations: ResourceDependencyObservation[] = [{ hostId: 'node-test', ownerHmac: 'a'.repeat(64), dependentResourceCount: 0, resourceHmacs: [], targets: [{ resourceId: resource, targetResourceHmac: 'b'.repeat(64), dependentCount: 0, dependencyFingerprint: fingerprint.repeat(64), fingerprintKeyId: 'fp-1' }] }];
      return { fresh: { state: 'ready' as const, resources: { [origin]: [resource] }, inventoryComplete: { [origin]: true }, dependencies: { [origin]: { count: 0, hashes: [] } }, unavailableHosts: [] }, observations, snapshot: buildReviewSnapshot(hosts, observations) };
    };
    const resolutionKeys: string[] = [];
    const runtime: DeletionReviewRuntime = {
      completions: async () => [],
      check,
      authorize: async () => { throw Error('Zero needs no proof'); },
      purge: async (_id, _fresh, proof, resolution) => {
        expect(proof).toBeUndefined();
        const row = await db.accountDeletionReview.findUniqueOrThrow({ where: { eventKey: resolution.eventKey } });
        expect((row.summary as { snapshotHash: string }).snapshotHash).toBe(resolution.snapshotHash);
        resolutionKeys.push(resolution.eventKey);
        return false;
      },
      notify: async () => {},
    };
    const noSpaceWork = async (): Promise<never> => { throw Error('Resources are pending'); };
    const bad = await createJob('partial');
    await sweepAccountDeletions(db, noSpaceWork, { ...runtime, check: async () => { const value = await check(); return { ...value, fresh: { ...value.fresh, resources: {}, dependencies: {}, inventoryComplete: {} } }; } });
    expect(await db.accountDeletionReview.count({ where: { jobId: bad.id, kind: 'resolved: zero dependents' } })).toBe(0);
    expect((await db.accountDeletionJob.findUniqueOrThrow({ where: { id: bad.id } })).state).toBe('pending_review');
    expect(resolutionKeys).toHaveLength(0);
    const repeated = await createJob('repeated');
    await sweepAccountDeletions(db, noSpaceWork, runtime);
    fingerprint = 'd';
    await db.accountDeletionJob.update({ where: { id: repeated.id }, data: { nextAttemptAt: new Date(0) } });
    await sweepAccountDeletions(db, noSpaceWork, runtime);
    expect(resolutionKeys).toHaveLength(2);
    expect(new Set(resolutionKeys).size).toBe(2);
    const first = await db.accountDeletionReview.findUniqueOrThrow({ where: { eventKey: resolutionKeys[0] } });
    const second = await db.accountDeletionReview.findUniqueOrThrow({ where: { eventKey: resolutionKeys[1] } });
    expect((first.summary as { snapshotHash: string }).snapshotHash).not.toBe((second.summary as { snapshotHash: string }).snapshotHash);
    expect((await db.accountDeletionJob.findUniqueOrThrow({ where: { id: repeated.id } })).progress).toMatchObject({ activeReviewResolution: { eventKey: resolutionKeys[1] } });
    const race = await createJob('takeover');
    let release!: () => void;
    let entered!: () => void;
    const blocked = new Promise<void>(resolve => { release = resolve; });
    const started = new Promise<void>(resolve => { entered = resolve; });
    let firstCheck = true;
    const competing = { ...runtime, check: async () => { if (firstCheck) { firstCheck = false; entered(); await blocked; } return check(); } };
    const oldWorker = sweepAccountDeletions(db, noSpaceWork, competing);
    await started;
    await db.accountDeletionJob.update({ where: { id: race.id }, data: { leaseUntil: new Date(0), nextAttemptAt: new Date(0) } });
    await sweepAccountDeletions(db, noSpaceWork, competing);
    release(); await oldWorker;
    expect(await db.accountDeletionReview.count({ where: { jobId: race.id, kind: 'resolved: zero dependents' } })).toBe(1);
    expect(await db.ethereumKey.count({ where: { userId: 'takeover' } })).toBe(1);
    expect((await db.accountDeletionJob.findUniqueOrThrow({ where: { id: race.id } })).state).toBe('pending_review');
    const partial = await createJob('partial-purge');
    const other = resource.replace(':default', ':archive');
    await db.accountDeletionJob.update({ where: { id: partial.id }, data: { progress: { hostSnapshot: hosts, reviewTargets: { [origin]: [resource, other] } } } });
    let phase = 0;
    let purgeCalls = 0;
    const completeRecords: DurableResourceCompletion[] = [];
    const partialRuntime: DeletionReviewRuntime = {
      ...runtime,
      completions: async () => completeRecords,
      check: async () => {
        const inventory = phase === 0 ? [resource, other] : [other];
        const observations: ResourceDependencyObservation[] = [{ hostId: 'node-test', ownerHmac: 'a'.repeat(64), dependentResourceCount: 0, resourceHmacs: [], targets: inventory.map(resourceId => ({ resourceId, targetResourceHmac: (resourceId === resource ? 'b' : 'd').repeat(64), dependentCount: 0, dependencyFingerprint: 'c'.repeat(64), fingerprintKeyId: 'fp-1' })) }];
        return { fresh: { state: 'ready', resources: { [origin]: inventory }, inventoryComplete: { [origin]: true }, dependencies: { [origin]: { count: 0, hashes: [] } }, unavailableHosts: [] }, observations, snapshot: buildReviewSnapshot(hosts, observations) };
      },
      purge: async () => { purgeCalls += 1; if (phase === 0) return false; completeRecords.push({ jobId: partial.id, hostId: 'node-test', resourceId: other, purgeId: crypto.randomUUID(), state: 'complete' }); return true; },
    };
    const retryPartial = async () => {
      await db.accountDeletionJob.update({ where: { id: partial.id }, data: { nextAttemptAt: new Date(0) } });
      await sweepAccountDeletions(db, noSpaceWork, partialRuntime);
    };
    await retryPartial();
    phase = 1;
    await retryPartial(); // Inventory absence alone must NOT prune the target.
    expect(purgeCalls).toBe(1);
    expect((await db.accountDeletionJob.findUniqueOrThrow({ where: { id: partial.id } })).state).toBe('pending_review');
    completeRecords.push({ jobId: partial.id, hostId: 'node-test', resourceId: resource, purgeId: crypto.randomUUID(), state: 'complete' });
    await retryPartial();
    expect(purgeCalls).toBe(2);
    expect((await db.accountDeletionJob.findUniqueOrThrow({ where: { id: partial.id } })).state).toBe('deletion_requested');
    expect(await db.ethereumKey.count({ where: { userId: 'partial-purge' } })).toBe(1);

  } finally { await db.$disconnect(); await rm(dir, { recursive: true, force: true }); }
}, 90_000);
