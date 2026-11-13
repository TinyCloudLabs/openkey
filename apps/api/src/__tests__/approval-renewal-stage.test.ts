// TC-2933: the renewal lease steps are saved on the approval request only while this approval's admission
// holds, so a crashed attempt's saved grant and lease are what a retry collects, and nothing else can write them.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { APPROVAL_CLAIM_LEASE_MS, ApprovalResultService, type ApprovalRequestRecord } from '../services/approval-results';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import type { RenewalStage } from '../services/renewal-lease';

const MIGRATIONS = ['20261028_0001_approval_request_results', '20261103_0002_approval_request_denied', '20261109_0001_approval_request_approving', '20261113_0001_approval_request_renewal']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const MINUTE = 60_000;
const ID = 'abcdefghijklmnopqrstuvwxyz';

let database: PGlite;
let client: PrismaClient;
let clock = new Date('2026-11-13T12:00:00Z');

beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  for (const migration of MIGRATIONS) await database.exec(await readFile(migration, 'utf8'));
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
});
afterAll(async () => {
  await client.$disconnect();
  await database.close();
});
beforeEach(async () => {
  await client.approvalRequest.deleteMany();
  clock = new Date('2026-11-13T12:00:00Z');
});

const store = () => createPrismaApprovalRequestStore(client);
const service = () => new ApprovalResultService(store(), { apiOrigin: 'http://localhost:3001', retentionSeconds: 600, now: () => clock });
const register = () => store().register({
  id: ID, bodyCid: 'sealed-body-cid', issuer: 'synthetic-requester',
  request: { targetDid: 'synthetic-requester' } as unknown as ApprovalRequestRecord['request'],
  expiresAt: new Date(clock.getTime() + 30 * MINUTE), createdAt: clock,
  resultRef: null, encryptedResult: null, resultExpiresAt: null,
});
const stage = (extra: Partial<RenewalStage> = {}): RenewalStage => ({
  version: 1, userId: 'owner', approvedAt: '2026-11-13T12:00:00.000Z', approvedLeaseLifetimeSeconds: 3600,
  leaseExpiresAt: '2026-11-13T13:00:00.000Z',
  nodeIdentity: { nodeDid: 'did:key:z6MkNode', renewerDid: 'did:key:z6MkRenewer', renewerPublicKey: 'pk', renewerEpoch: 0 },
  delegation: { delegationCid: 'bafy-original' }, originalCid: 'bafy-original', originalAuthorization: 'original',
  ownerAddress: '0x1111111111111111111111111111111111111111', chainId: 1, spaceId: 'tinycloud:pkh:eip155:1:0x1:agents',
  leaseNonce: 'nonce', leaseSiwe: 'lease message', ...extra,
});

describe('saving renewal lease steps', () => {
  test('are saved while this admission holds, and read back intact', async () => {
    await register();
    const marker = await service().admit(ID);
    await service().saveRenewal(ID, stage(), marker);
    await service().saveRenewal(ID, stage({ leaseAuthorization: 'signed-lease', leaseCid: 'bafy-lease' }), marker);
    expect((await store().findById(ID))!.renewal).toEqual(stage({ leaseAuthorization: 'signed-lease', leaseCid: 'bafy-lease' }));
  });

  test('are refused once another approval attempt has been admitted in place of this one', async () => {
    await register();
    const first = await service().admit(ID);
    clock = new Date(clock.getTime() + APPROVAL_CLAIM_LEASE_MS + 1);
    await service().admit(ID);
    await expect(service().saveRenewal(ID, stage(), first)).rejects.toMatchObject({ code: 'expired_request' });
    expect((await store().findById(ID))!.renewal).toBeNull();
  });

  test('are refused once the request has its result', async () => {
    await register();
    const marker = await service().admit(ID);
    await store().approve(ID, {
      resultRef: 'ref', approvedByUserId: 'owner', ownerDid: 'did:pkh:eip155:1:0x1', encryptedResult: '{}',
      delegationExpiresAt: new Date(clock.getTime() + 60 * MINUTE), resultExpiresAt: new Date(clock.getTime() + 10 * MINUTE),
    }, clock, marker);
    await expect(service().saveRenewal(ID, stage(), marker)).rejects.toMatchObject({ code: 'expired_request' });
  });
});
