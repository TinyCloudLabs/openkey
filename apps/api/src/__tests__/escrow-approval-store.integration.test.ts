import { expect, test } from 'bun:test';
import { Client } from 'pg';
import { PrismaClient } from '@openkey/db';
import { PrismaPg } from '@prisma/adapter-pg';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { createEscrowAuthorizationStore } from '../services/escrow-approval-store';

const run = process.env.OPENKEY_ESCROW_TEST_PG === '1' ? test : test.skip;
run('real SQL atomically consumes nonce with audit and serializes the rate limit', async () => {
  const local = { host: '/home/tinycloud/scratch/openkey-key-escrow/postgres', port: 55483, database: 'postgres', user: 'tinycloud' };
  const setup = new Client(local); await setup.connect();
  const schema = 'escrow_auth_' + crypto.randomUUID().replaceAll('-', '');
  await setup.query(`CREATE SCHEMA "${schema}"`); await setup.query(`SET search_path TO "${schema}"`);
  const prisma = new PrismaClient({ adapter: new PrismaPg({ ...local, options: `-c search_path=${schema}` }) });
  try {
    await setup.query(readFileSync(new URL('../../../../packages/db/prisma/migrations/20261111_escrow_authorization/migration.sql', import.meta.url), 'utf8'));
    await setup.query(readFileSync(new URL('../../../../packages/db/prisma/migrations/20261111_escrow_preflight/migration.sql', import.meta.url), 'utf8'));
    const seed = async (request: { policyHash: string; nonce: string; expiresAt: string }) => setup.query('INSERT INTO escrow_preflight ("policyHash",nonce,"expiresAt",payload) VALUES ($1,$2,$3,\'{}\')', [request.policyHash, request.nonce, request.expiresAt]);
    const store = createEscrowAuthorizationStore(prisma);
    const request = { kind: 'export' as const, nonce: randomBytes(32).toString('base64url'), policyHash: 'a'.repeat(64), operatorId: 'operator', approverId: 'approver', dryRun: true, expiresAt: new Date(Date.now() + 60000).toISOString() };
    await seed(request);
    const race = await Promise.allSettled([store.consume(request), store.consume(request)]);
    expect(race.filter(result => result.status === 'fulfilled').length).toBe(1);
    expect(race.filter(result => result.status === 'rejected').length).toBe(1);
    await expect(store.consume({ ...request, policyHash: 'b'.repeat(64) })).rejects.toThrow();
    await expect(store.consume({ ...request, nonce: randomBytes(32).toString('base64url'), expiresAt: new Date(Date.now() - 1).toISOString() })).rejects.toThrow();
    for (let i = 0; i < 8; i++) {
      const next = { ...request, policyHash: randomBytes(32).toString('hex'), nonce: randomBytes(32).toString('base64url') };
      await seed(next); await store.consume(next);
    }
    await expect(store.consume({ ...request, kind: 'preflight', approverId: null })).rejects.toThrow();
    await store.consume({ ...request, kind: 'preflight', approverId: null, nonce: randomBytes(32).toString('base64url') });
    await expect(store.consume({ ...request, nonce: randomBytes(32).toString('base64url') })).rejects.toThrow('rate limited');
    const audit = (await setup.query('SELECT "policyHash", "operatorId", "approverId", "dryRun", "kind" FROM escrow_authorization')).rows;
    expect(audit.length).toBe(10);
    expect(audit.every(row => /^[a-f0-9]{64}$/.test(row.policyHash) && row.operatorId === request.operatorId && ((row.kind === 'export' && row.approverId === request.approverId) || (row.kind === 'preflight' && row.approverId === null)) && row.dryRun === true)).toBe(true);
  } finally {
    await prisma.$disconnect(); await setup.query(`DROP SCHEMA "${schema}" CASCADE`); await setup.end();
  }
});
