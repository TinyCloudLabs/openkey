import { expect, test } from 'bun:test';
import { Client } from 'pg';
import { PrismaClient } from '@openkey/db';
import { PrismaPg } from '@prisma/adapter-pg';
import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { storeEscrowPreflight, loadEscrowPreflight } from '../services/escrow-preflight-store';
import { createEscrowAuthorizationStore } from '../services/escrow-approval-store';
import vector from '../../../../packages/tee/tests/fixtures/escrow-approval-v1.json';
import type { ExportPolicy } from '@openkey/tee';
const run = process.env.OPENKEY_ESCROW_TEST_PG === '1' ? test : test.skip;
run('private preflight is immutable, expiring and consumed atomically with its approval audit', async () => {
  const local = { host: '/home/tinycloud/scratch/openkey-key-escrow/postgres', port: 55483, database: 'postgres', user: 'tinycloud' };
  const setup = new Client(local); await setup.connect();
  const schema = 'escrow_preflight_' + crypto.randomUUID().replaceAll('-', '');
  await setup.query(`CREATE SCHEMA "${schema}"`); await setup.query(`SET search_path TO "${schema}"`);
  const prisma = new PrismaClient({ adapter: new PrismaPg({ ...local, options: `-c search_path=${schema}` }) });
  try {
    for (const name of ['authorization', 'preflight']) await setup.query(readFileSync(new URL(`../../../../packages/db/prisma/migrations/20261111_escrow_${name}/migration.sql`, import.meta.url), 'utf8'));
    const recordManifestUtf8 = '["tinycloud/escrow/record-manifest",1,[]]';
    const dbSnapshotUtf8 = '["tinycloud/escrow/db-snapshot",1,[]]';
    const policy: ExportPolicy = { ...vector.preflightHeader as ExportPolicy, nonce: randomBytes(32).toString('base64url'), expiresAt: new Date(Date.now() + 60000).toISOString(), recordManifestHash: createHash('sha256').update(recordManifestUtf8).digest('hex'), dbSnapshotHash: createHash('sha256').update(dbSnapshotUtf8).digest('hex') };
    const input = { policy, recordManifestUtf8, dbSnapshotUtf8 };
    const hash = await prisma.$transaction(tx => storeEscrowPreflight(tx, input));
    expect((await loadEscrowPreflight(prisma, hash)).policy.nonce).toBe(policy.nonce);
    await expect(prisma.$transaction(tx => storeEscrowPreflight(tx, input))).rejects.toThrow();
    const auth = createEscrowAuthorizationStore(prisma);
    await auth.consume({ kind: 'export', nonce: policy.nonce, policyHash: hash, expiresAt: policy.expiresAt, operatorId: policy.operatorId, approverId: policy.approverId, dryRun: false });
    await expect(loadEscrowPreflight(prisma, hash)).rejects.toThrow();
    expect((await setup.query('SELECT count(*)::int AS count FROM escrow_authorization')).rows[0]!.count).toBe(1);
    expect((await setup.query('SELECT "consumedAt" IS NOT NULL AS used FROM escrow_preflight')).rows[0]!.used).toBe(true);
    const next = { ...input, policy: { ...policy, nonce: randomBytes(32).toString('base64url') } };
    const nextHash = await prisma.$transaction(tx => storeEscrowPreflight(tx, next));
    await setup.query('UPDATE escrow_preflight SET "expiresAt" = clock_timestamp() - INTERVAL \'1 second\' WHERE "policyHash"=$1', [nextHash]);
    await expect(loadEscrowPreflight(prisma, nextHash)).rejects.toThrow();
  } finally { await prisma.$disconnect(); await setup.query(`DROP SCHEMA "${schema}" CASCADE`); await setup.end(); }
});
