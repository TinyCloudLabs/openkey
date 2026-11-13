import { test, expect } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createPrismaClient } from '@openkey/db';
import { commitDeletionRequest } from './account-deletion-request';
import { sweepAccountDeletions } from './account-deletion-sweep';
import type { DeletionAdapter } from './account-deletion-job';

test('database restart retains progress and keys until all hosts finish', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'openkey-deletion-'));
  const migrationRoot = resolve(import.meta.dir, '../../../../packages/db/prisma/migrations');
  const database = new PGlite(dir);
  for (const name of (await readdir(migrationRoot)).sort()) {
    if (name === 'migration_lock.toml') continue;
    await database.exec(await readFile(join(migrationRoot, name, 'migration.sql'), 'utf8'));
  }
  await database.close();
  const connect = () => createPrismaClient({ connectionString: `pglite:${dir}` });
  let db = connect();
  try {
    await db.user.create({ data: { id: 'owner', email: 'owner@example.test' } });
    await db.ethereumKey.create({ data: { id: 'key', userId: 'owner', address: 'synthetic', publicKey: 'synthetic', sealedBlob: 'synthetic' } });
    await db.session.create({ data: { id: 'session', userId: 'owner', token: 'synthetic-token', expiresAt: new Date(Date.now() + 60_000) } });
    await db.$transaction(tx => commitDeletionRequest(tx, 'owner', [{ hostId: 'a', url: 'a' }, { hostId: 'b', url: 'b' }, { hostId: 'production', url: 'https://node.tinycloud.xyz' }]));
    const jobId = (await db.accountDeletionJob.findUniqueOrThrow({ where: { userId: 'owner' } })).id;
    expect(jobId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(await db.session.count()).toBe(0);
    // A newly attempted session must be refused even while key rows exist.
    process.env.DATABASE_URL = `pglite:${dir}`;
    process.env.NODE_ENV = 'test';
    process.env.BETTER_AUTH_SECRET = 'synthetic-account-deletion-test-secret';
    process.env.BETTER_AUTH_URL = 'https://api.openkey.test';
    process.env.WEBAUTHN_RP_ID = 'openkey.test';
    process.env.WEBAUTHN_ORIGIN = 'https://openkey.test';
    process.env.CORS_ORIGIN = 'https://openkey.test';
    const authModule = await import('../auth');
    try {
      const before = authModule.auth.options.databaseHooks!.session!.create!.before!;
      await expect(before({ userId: 'owner' } as never)).rejects.toThrow('Account unavailable');
    } finally { await authModule.prisma.$disconnect(); }
    let offline = true;
    let done = false;
    const calls: string[] = [];
    const adapter: DeletionAdapter = {
      hosts: async () => ['a', 'b'], recordedHosts: async () => ['a'],
      retire: async host => { calls.push(`retire:${host}`); if (host === 'b' && offline) throw Error(); },
      list: async host => { calls.push(`list:${host}`); return ['openkey', 'secrets', 'other-app']; },
      purge: async (_host, _space, key) => ({ purgeId: key, complete: false }), status: async () => done,
    };
    const tick = async () => {
      await db.accountDeletionJob.update({ where: { id: jobId }, data: { nextAttemptAt: new Date(0) } });
      await sweepAccountDeletions(db, async () => adapter);
    };
    await tick();
    expect(calls.some(call => call.startsWith('list:'))).toBe(false);
    expect(await db.ethereumKey.count()).toBe(1);
    await db.accountDeletionJob.update({ where: { id: jobId }, data: { leaseToken: 'crashed-worker', leaseUntil: new Date(Date.now() + 60_000) } });
    await db.$disconnect();
    db = connect();
    const callsBeforeLeaseExpiry = calls.length;
    await tick();
    expect(calls.length).toBe(callsBeforeLeaseExpiry);
    await db.accountDeletionJob.update({ where: { id: jobId }, data: { leaseUntil: new Date(0) } });
    adapter.hosts = async () => ['later-host'];
    offline = false;
    await tick();
    expect(calls.filter(call => call === 'retire:a')).toHaveLength(1);
    expect(calls).not.toContain('retire:later-host');
    expect(await db.ethereumKey.count()).toBe(1);
    expect((await db.user.findUniqueOrThrow({ where: { id: 'owner' } })).lockedAt).not.toBeNull();
    done = true;
    await tick();
    expect(await db.ethereumKey.count()).toBe(0);
    expect(await db.user.count()).toBe(0);
    expect((await db.accountDeletionJob.findUniqueOrThrow({ where: { id: jobId } })).state).toBe('complete');
  } finally { await db.$disconnect(); await rm(dir, { recursive: true, force: true }); }
}, 90_000);
