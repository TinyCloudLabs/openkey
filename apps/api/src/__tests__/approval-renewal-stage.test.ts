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

const MIGRATIONS = ['20261028_0001_approval_request_results', '20261103_0002_approval_request_denied', '20261109_0001_approval_request_approving', '20261113_0001_approval_request_renewal', '20261113_0002_renewal_lease', '20261113_0003_renewal_lease_reservation']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const MINUTE = 60_000;
const ID = 'abcdefghijklmnopqrstuvwxyz';

let database: PGlite;
let client: PrismaClient;
let clock = new Date('2026-11-13T12:00:00Z');

beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  // The lease record belongs to an OpenKey user; only its key matters here.
  await database.exec('CREATE TABLE "user" ("id" TEXT NOT NULL PRIMARY KEY); INSERT INTO "user" ("id") VALUES (\'owner\');');
  for (const migration of MIGRATIONS) await database.exec(await readFile(migration, 'utf8'));
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
});
afterAll(async () => {
  await client.$disconnect();
  await database.close();
});
beforeEach(async () => {
  await client.renewalLease.deleteMany();
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

  test('are cleared when the result is saved, and stay cleared through its acknowledgement', async () => {
    await register();
    const marker = await service().admit(ID);
    await service().saveRenewal(ID, stage({ leaseAuthorization: 'signed-lease', leaseCid: 'bafy-lease' }), marker);
    expect(await store().approve(ID, {
      resultRef: 'ref', approvedByUserId: 'owner', ownerDid: 'did:pkh:eip155:1:0x1', encryptedResult: '{}',
      delegationExpiresAt: new Date(clock.getTime() + 60 * MINUTE), resultExpiresAt: new Date(clock.getTime() + 10 * MINUTE),
    }, clock, marker)).toBe(true);
    expect((await store().findById(ID))!.renewal).toBeNull();
    expect(await store().acknowledge('ref', 'durable-ack-intent-0001', clock)).not.toBeNull();
    const acknowledged = (await store().findById(ID))!;
    expect(acknowledged.renewal).toBeNull();
    expect(acknowledged.encryptedResult).toBeNull();
  });

  test('are cleared from a request that expired without a result, at the next admission', async () => {
    await register();
    const marker = await service().admit(ID);
    await service().saveRenewal(ID, stage(), marker);
    clock = new Date(clock.getTime() + 31 * MINUTE + APPROVAL_CLAIM_LEASE_MS);
    const other = 'zyxwvutsrqponmlkjihgfedcba';
    await store().register({
      id: other, bodyCid: 'other-body-cid', issuer: 'synthetic-requester',
      request: { targetDid: 'synthetic-requester' } as unknown as ApprovalRequestRecord['request'],
      expiresAt: new Date(clock.getTime() + 30 * MINUTE), createdAt: clock,
      resultRef: null, encryptedResult: null, resultExpiresAt: null,
    });
    await service().admit(other);
    expect((await store().findById(ID))!.renewal).toBeNull();
  });
});

describe('the lasting lease record', () => {
  const result = (resultRef: string) => ({
    resultRef, approvedByUserId: 'owner', ownerDid: 'did:pkh:eip155:1:0x1', encryptedResult: '{}',
    delegationExpiresAt: new Date(clock.getTime() + 60 * MINUTE), resultExpiresAt: new Date(clock.getTime() + 10 * MINUTE),
  });
  const lease = {
    leaseCid: 'bafy-lease', userId: 'owner', sessionId: 'session-1', approvalRequestId: ID, ownerDid: 'did:pkh:eip155:1:0x1',
    originalCid: 'bafy-original', nodeOrigin: 'https://node.tinycloud.xyz', nodeDid: 'did:key:z6MkNode', renewerDid: 'did:key:z6MkRenewer',
    leaseLifetimeSeconds: 3600, approvedAt: new Date('2026-11-13T12:00:00.000Z'), leaseExpiresAt: new Date('2026-11-13T13:00:00.000Z'),
  };
  // TC-2946: the record is reserved before the node admits the lease; the approval confirms it.
  const reserve = () => client.renewalLease.create({ data: { ...lease, sessionId: null, grantSiwe: 'grant', leaseAuthorization: 'sealed-lease' } });

  test('is confirmed by the leased approval that wins, and survives acknowledgement', async () => {
    await register();
    await reserve();
    const marker = await service().admit(ID);
    expect(await store().approve(ID, { ...result('ref'), lease }, clock, marker!)).toBe(true);
    await store().acknowledge('ref', 'durable-ack-intent-0001', clock);
    expect(await client.renewalLease.findMany()).toEqual([{
      ...lease, grantSiwe: 'grant', createdAt: expect.any(Date), revokedAt: null, neverAdmittedAt: null, admittedAt: clock, leaseAuthorization: null,
    }]);
  });

  test('is not confirmed by an approval that loses, and a losing write leaves no partial approval', async () => {
    await register();
    await reserve();
    const marker = await service().admit(ID);
    expect(await store().approve(ID, result('first'), clock, marker!)).toBe(true);
    expect(await store().approve(ID, { ...result('second'), lease }, clock, marker!)).toBe(false);
    expect((await client.renewalLease.findUniqueOrThrow({ where: { leaseCid: lease.leaseCid } })).admittedAt).toBeNull();
    expect((await store().findById(ID))!.resultRef).toBe('first');
  });

  test('approves nothing when the lease was never reserved or was stopped meanwhile', async () => {
    for (const reserved of [false, true]) {
      await client.renewalLease.deleteMany();
      await client.approvalRequest.deleteMany();
      await register();
      if (reserved) await client.renewalLease.create({ data: { ...lease, grantSiwe: 'grant', revokedAt: clock } });
      const marker = await service().admit(ID);
      expect(await store().approve(ID, { ...result('ref'), lease }, clock, marker!)).toBe(false);
      const record = (await store().findById(ID))!;
      expect(record.resultRef).toBeNull();
      expect(record.encryptedResult).toBeNull();
    }
  });
});
