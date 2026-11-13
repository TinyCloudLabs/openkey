import type { DurableResourceCompletion } from './account-deletion-review-completions';
import { test, expect } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createPrismaClient } from '@openkey/db';
import { sweepAccountDeletions } from './account-deletion-sweep';
import { signDeadlineReviewDecisions, signResourceReviewDecision, type HostRow, type ResourceDependencyObservation } from './account-deletion-decision';
import { recordDeletionReviewDecision, claimDeadlineSigningRecord } from './account-deletion-review-ledger';
import type { DeletionReviewRuntime } from './account-deletion-review-worker';

const origin = 'https://node.example.test';
const hosts = { configured: [{ hostId: 'node-test', url: origin }], recorded: [origin], uncertain: false };
const resource = 'urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';

test('review sweep resumes fresh zero and wait, alerts before deadline, signs once and retains pending keys', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'tc2871-review-worker-'));
  const database = new PGlite(dir);
  const migrations = resolve(import.meta.dir, '../../../../packages/db/prisma/migrations');
  try { for (const name of (await readdir(migrations)).sort()) if (name !== 'migration_lock.toml') await database.exec(await readFile(join(migrations, name, 'migration.sql'), 'utf8')); }
  finally { await database.close(); }
  const db = createPrismaClient({ connectionString: `pglite:${dir}` });
  try {
    const { privateKey } = generateKeyPairSync('ed25519');
    const jobIds: Record<string, string> = {};
    const age = { zero: 2, wait: 3, held: 6, deadline: 7, operator: 2, stale: 2, expired: 2, late: 7 };
    for (const [name, days] of Object.entries(age)) {
      await db.user.create({ data: { id: name, email: `${name}@example.test` } });
      await db.ethereumKey.create({ data: { id: name, userId: name, address: `synthetic-${name}`, publicKey: 'synthetic', sealedBlob: 'synthetic' } });
      await db.session.create({ data: { id: name, userId: name, token: `synthetic-${name}`, expiresAt: new Date(Date.now() + 60_000) } });
      const job = await db.accountDeletionJob.create({ data: { userId: name, state: name === 'wait' ? 'wait_for_re_encryption' : 'pending_review', progress: { hostSnapshot: hosts, reviewTargets: { [origin]: [resource] } }, requestedAt: new Date(Date.now() - days * 86_400_000) } });
      jobIds[name] = job.id;
    }
    let authorizations = 0;
    let revoked = false;
    const purged: string[] = [];
    const alerts: string[] = [];
    const counts = (id: string) => id === jobIds.zero || id === jobIds.wait ? 0 : 1;
    const observations = (id: string): ResourceDependencyObservation[] => [{ hostId: 'node-test', ownerHmac: 'a'.repeat(64), dependentResourceCount: counts(id), resourceHmacs: counts(id) ? ['b'.repeat(64)] : [], targets: [{ resourceId: resource, targetResourceHmac: 'b'.repeat(64), dependentCount: counts(id), dependencyFingerprint: 'c'.repeat(64), fingerprintKeyId: 'fp-1' }] }];
    const completed: DurableResourceCompletion[] = [];
    const runtime: DeletionReviewRuntime = {
      completions: async id => completed.filter(record => record.jobId === id),
      check: async id => ({ fresh: { state: counts(id) ? 'pending_review' : 'ready', resources: { [origin]: [resource] }, dependencies: { [origin]: { count: counts(id), hashes: counts(id) ? ['b'.repeat(64)] : [] } }, unavailableHosts: [], inventoryComplete: { [origin]: true } }, observations: observations(id), snapshot: [['node-test', 'a'.repeat(64), counts(id), counts(id) ? ['b'.repeat(64)] : [], [['b'.repeat(64), counts(id), 'c'.repeat(64), 'fp-1']]]] }),
      authorize: async (id, mode, _snapshot, decision) => {
        authorizations += 1;
        if (mode === 'operator') {
          const now = Math.floor(Date.now() / 1000);
          return [await signResourceReviewDecision({ decisionId: crypto.randomUUID(), jobId: id, hostId: 'node-test', resourceId: resource, disposition: 'proceed', decisionMaker: 'Naomi', decidedAt: now, expiresAt: now + 172800, reason: 'Operator reviewed current snapshot', reviewedSnapshot: decision?.snapshot }, hosts, observations(id), { writerId: 'review-test', keyId: 'test-1', sign: async bytes => sign(null, bytes, privateKey) })];
        }
        return signDeadlineReviewDecisions(id, hosts, observations(id), {
          writerId: 'review-test', keyId: 'test-1', sign: async bytes => sign(null, bytes, privateKey),
          // Synthetic verified-ledger/TEE adapters only; no production key.
          verifiedRequest: async jobId => { const row = await db.accountDeletionJob.findUniqueOrThrow({ where: { id: jobId } }); return { jobId, requestId: jobId, requestedAt: Math.floor(row.requestedAt.getTime() / 1000), hosts, ownerHmacs: { 'node-test': 'a'.repeat(64) } }; },
          teeNow: async () => Math.floor(Date.now() / 1000), deadlineRevoked: async () => revoked,
          claimDeadline: (jobId, requestId, nonce) => claimDeadlineSigningRecord(db, jobId, requestId, nonce),
        });
      },
      purge: async (id, _fresh, proofs, resolution) => {
        const audit = await db.accountDeletionReview.findUniqueOrThrow({ where: { eventKey: resolution.eventKey } });
        expect((audit.summary as { snapshotHash: string }).snapshotHash).toBe(resolution.snapshotHash);
        purged.push(id);
        if (id === jobIds.deadline) {
          expect(proofs?.[0]?.payload[9]).toBe('deadline');
          if (revoked) throw Error('Revoked');
          return false;
        }
        if (id === jobIds.operator) expect(proofs?.[0]?.payload[9]).toBe('Naomi');
        else expect(proofs).toBeUndefined();
        completed.push({ jobId: id, hostId: 'node-test', resourceId: resource, purgeId: crypto.randomUUID(), state: 'complete' });
        return true;
      },
      notify: async (id, key) => { alerts.push(key); if (id === jobIds.zero) throw Error('Alert transport unavailable'); },
    };
    for (const name of ['operator', 'stale', 'expired']) {
      const reviewed: HostRow[] = [['node-test', 'a'.repeat(64), 1, ['b'.repeat(64)], [['b'.repeat(64), 1, (name === 'stale' ? 'd' : 'c').repeat(64), 'fp-1']]]];
      const at = new Date(Date.now() - (name === 'expired' ? 172800_000 : 0));
      await db.$transaction(tx => recordDeletionReviewDecision(tx, jobIds[name]!, { actor: 'Naomi', at, reason: 'Review recorded', disposition: 'proceed', snapshot: reviewed }));
    }
    const deadlineRequest = await db.accountDeletionJob.findUniqueOrThrow({ where: { id: jobIds.deadline } });
    for (const [key, offset] of [['day-1', 86_400_000], ['day-6', 6 * 86_400_000]] as const) await db.accountDeletionReview.create({ data: { jobId: jobIds.deadline!, eventKey: `${jobIds.deadline}:review-${key}`, kind: 'operator_alert', summary: { code: key }, deliveredAt: new Date(deadlineRequest.requestedAt.getTime() + offset) } });
    const noSpaceWork = async (): Promise<never> => { throw Error('Resource review must run first'); };
    await sweepAccountDeletions(db, noSpaceWork, runtime);
    for (const name of ['zero', 'wait']) {
      const row = await db.accountDeletionJob.findUniqueOrThrow({ where: { id: jobIds[name] } });
      expect(row.state).toBe('deletion_requested');
      expect(await db.accountDeletionReview.count({ where: { jobId: row.id, kind: 'resolved: zero dependents' } })).toBe(1);
      expect(row.requestedAt.getTime()).toBeLessThan(Date.now() - 86_400_000);
    }
    expect(purged).not.toContain(jobIds.held);
    expect(purged).not.toContain(jobIds.stale);
    expect(purged).not.toContain(jobIds.expired);
    expect(purged).not.toContain(jobIds.late);
    expect(alerts).toContain(`${jobIds.late}:review-missed-predeadline-alert`);
    expect(purged).toContain(jobIds.operator!);
    expect(alerts).toContain(`${jobIds.held}:review-day-1`);
    expect(alerts).toContain(`${jobIds.held}:review-day-6`);
    expect(authorizations).toBe(3);
    const proofEvent = await db.accountDeletionReview.findUniqueOrThrow({ where: { eventKey: `${jobIds.deadline}:deadline-proofs` } });
    expect(proofEvent.actor).toBe('deadline');
    expect(proofEvent.disposition).toBe('proceed');
    expect((await db.accountDeletionJob.findUniqueOrThrow({ where: { id: jobIds.deadline } })).state).toBe('pending_review');
    expect(await db.ethereumKey.count()).toBe(Object.keys(age).length);
    expect(await db.session.count()).toBe(0);
    expect(await db.user.count({ where: { lockedAt: { not: null } } })).toBe(Object.keys(age).length);
    revoked = true;
    await db.accountDeletionJob.update({ where: { id: jobIds.deadline }, data: { nextAttemptAt: new Date(0) } });
    await sweepAccountDeletions(db, noSpaceWork, runtime);
    expect(authorizations).toBe(3);
    expect(alerts).toContain(`${jobIds.deadline}:review-authorization-escalation`);
    expect(await db.accountDeletionJob.count({ where: { state: 'complete' } })).toBe(0);
    expect(await db.ethereumKey.count()).toBe(Object.keys(age).length);
    expect(await db.accountDeletionReview.count({ where: { jobId: jobIds.deadline, kind: 'deadline-attempt' } })).toBe(1);
    const claimResults = await Promise.all([claimDeadlineSigningRecord(db, jobIds.held!, jobIds.held!, crypto.randomUUID()), claimDeadlineSigningRecord(db, jobIds.held!, jobIds.held!, crypto.randomUUID())]);
    expect(claimResults.filter(Boolean)).toHaveLength(1);
  } finally { await db.$disconnect(); await rm(dir, { recursive: true, force: true }); }
}, 90_000);
