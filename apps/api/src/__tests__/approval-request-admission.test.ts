// TC-2615: an approval request is admitted once, before signing starts. The admission checks expiry and sets
// one `approving` marker; approve and deny each settle a request exactly once.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { APPROVAL_CLAIM_LEASE_MS, ApprovalResultService, type ApprovalRequestRecord } from '../services/approval-results';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';

const MIGRATIONS = ['20261028_0001_approval_request_results', '20261103_0002_approval_request_denied', '20261109_0001_approval_request_approving', '20261113_0001_approval_request_renewal']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const MINUTE = 60_000;
const ID = 'abcdefghijklmnopqrstuvwxyz';
const LINK = { bodyCid: 'sealed-body-cid', issuer: 'synthetic-requester' };

let database: PGlite;
let client: PrismaClient;
let clock = new Date('2026-11-09T12:00:00Z');

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
  clock = new Date('2026-11-09T12:00:00Z');
});

const store = () => createPrismaApprovalRequestStore(client);
const service = () => new ApprovalResultService(store(), { apiOrigin: 'http://localhost:3001', retentionSeconds: 600, now: () => clock });
const registered = (expiresInMs = 30 * MINUTE) => store().register({
  id: ID, bodyCid: LINK.bodyCid, issuer: LINK.issuer,
  request: { targetDid: 'synthetic-requester' } as unknown as ApprovalRequestRecord['request'],
  expiresAt: new Date(clock.getTime() + expiresInMs), createdAt: clock,
  resultRef: null, encryptedResult: null, resultExpiresAt: null,
});
const result = (ref = 'synthetic-result-reference') => ({
  resultRef: ref, approvedByUserId: 'owner', ownerDid: 'did:pkh:eip155:1:0x1',
  encryptedResult: '{"ciphertext":"opaque"}', delegationExpiresAt: new Date(clock.getTime() + 60 * MINUTE),
  resultExpiresAt: new Date(clock.getTime() + 10 * MINUTE),
});
const advance = (ms: number) => { clock = new Date(clock.getTime() + ms); };

describe('admitting an approval request', () => {
  test('refuses an expired request before anything is signed', async () => {
    await registered(MINUTE);
    advance(2 * MINUTE);
    await expect(service().admit(ID)).rejects.toMatchObject({ code: 'expired_request', status: 410 });
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).approvingAt).toBeNull();
  });

  test('admits a pending request once; a second admission is refused while the first is in flight', async () => {
    await registered();
    await service().admit(ID);
    await expect(service().admit(ID)).rejects.toMatchObject({ code: 'approval_in_progress', status: 409 });
  });

  test('a request that expires while it is being signed is still saved by the admitted approval', async () => {
    await registered(10_000);
    const marker = await service().admit(ID);
    advance(20_000);
    expect(await store().approve(ID, result(), clock, marker)).toBe(true);
  });

  test('a slow attempt past the lease still saves while nothing replaced its marker', async () => {
    await registered();
    const marker = await service().admit(ID);
    advance(APPROVAL_CLAIM_LEASE_MS + 1_000);
    expect(await store().approve(ID, result(), clock, marker)).toBe(true);
  });

  test('after the lease lapses a deny settles the request and the slow save is refused', async () => {
    await registered();
    const marker = await service().admit(ID);
    advance(APPROVAL_CLAIM_LEASE_MS + 1_000);
    await expect(service().deny(ID, LINK)).resolves.toEqual({ status: 'denied' });
    expect(await store().approve(ID, result(), clock, marker)).toBe(false);
  });

  test('after the lease lapses a re-admission replaces the marker, and the first attempt cannot save', async () => {
    await registered();
    const first = await service().admit(ID);
    advance(APPROVAL_CLAIM_LEASE_MS + 1_000);
    const second = await service().admit(ID);
    expect(await store().approve(ID, result('first'), clock, first)).toBe(false);
    expect(await store().approve(ID, result('second'), clock, second)).toBe(true);
  });

  test('a marker a day old on a long-expired request cannot save', async () => {
    await registered(MINUTE);
    const marker = await service().admit(ID);
    advance(24 * 60 * MINUTE);
    expect(await store().approve(ID, result(), clock, marker)).toBe(false);
  });

  test('a marker that is not the one on the request cannot save', async () => {
    await registered();
    await service().admit(ID);
    expect(await store().approve(ID, result(), clock, new Date(clock.getTime() - 1))).toBe(false);
    expect(await store().approve(ID, result(), clock, new Date(clock.getTime() + 1))).toBe(false);
  });

  test('an unmarked save is refused while another approval is in flight', async () => {
    await registered();
    await service().admit(ID);
    expect(await store().approve(ID, result(), clock)).toBe(false);
  });

  test('releasing the marker lets deny and a new admission proceed at once', async () => {
    await registered();
    const marker = await service().admit(ID);
    await service().release(ID, marker);
    await service().admit(ID);
    const second = (await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).approvingAt!;
    await service().release(ID, second);
    await expect(service().deny(ID, LINK)).resolves.toEqual({ status: 'denied' });
  });

  test('releasing with a marker that is not current changes nothing', async () => {
    await registered();
    const marker = await service().admit(ID);
    await service().release(ID, new Date(marker.getTime() - 1));
    await expect(service().deny(ID, LINK)).rejects.toMatchObject({ code: 'approval_in_progress' });
  });

  test('an unadmitted save still needs an unexpired request', async () => {
    await registered(MINUTE);
    advance(2 * MINUTE);
    expect(await store().approve(ID, result(), clock)).toBe(false);
  });

  test('an abandoned admission can be taken again once its lease is over', async () => {
    await registered();
    await service().admit(ID);
    advance(APPROVAL_CLAIM_LEASE_MS + 1);
    await service().admit(ID);
  });

  test('a denied, approved or unknown request is not admitted', async () => {
    await registered();
    await service().deny(ID, LINK);
    await expect(service().admit(ID)).rejects.toMatchObject({ code: 'expired_request', extra: { status: 'denied' } });
    await expect(service().admit('unknown-request-id')).rejects.toMatchObject({ code: 'expired_request' });
    await client.approvalRequest.deleteMany();
    await registered();
    expect(await store().approve(ID, result(), clock)).toBe(true);
    await expect(service().admit(ID)).rejects.toMatchObject({ code: 'expired_request', status: 410 });
  });
});

describe('settling an approval request exactly once', () => {
  test('deny is refused while an approval is in flight, and the approval then saves', async () => {
    await registered();
    const marker = await service().admit(ID);
    await expect(service().deny(ID, LINK)).rejects.toMatchObject({ code: 'approval_in_progress', status: 409 });
    expect(await store().approve(ID, result(), clock, marker)).toBe(true);
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).deniedAt).toBeNull();
  });

  test('deny works again when the approval in flight was abandoned', async () => {
    await registered();
    await service().admit(ID);
    advance(APPROVAL_CLAIM_LEASE_MS + 1);
    await expect(service().deny(ID, LINK)).resolves.toEqual({ status: 'denied' });
    expect(await store().approve(ID, result(), clock)).toBe(false);
  });

  test('approve and deny racing: exactly one settles the request', async () => {
    for (let round = 0; round < 5; round++) {
      await client.approvalRequest.deleteMany();
      await registered();
      const [approved, denied] = await Promise.all([store().approve(ID, result(), clock), store().deny(ID, clock)]);
      expect([approved, denied].filter(Boolean)).toHaveLength(1);
      const row = await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } });
      expect(Boolean(row.resultRef) !== Boolean(row.deniedAt)).toBe(true);
    }
  });

  test('two approvals: only the first saves a result', async () => {
    await registered();
    const marker = await service().admit(ID);
    expect(await store().approve(ID, result('first'), clock, marker)).toBe(true);
    expect(await store().approve(ID, result('second'), clock, marker)).toBe(false);
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).resultRef).toBe('first');
  });
});
