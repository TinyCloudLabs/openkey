// TC-2615: the admitted approval is saved by the real service path (checks, encryption, store) even when
// the request's deadline passed while it was signed; a failed attempt gives the admission back.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { PrismaClient } from '@openkey/db';
import { APPROVAL_CLAIM_LEASE_MS, ApprovalResultService, type ApprovalRequestRecord } from '../services/approval-results';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import { strictSessionDid } from '../services/device-authorization';

const MIGRATIONS = ['20261028_0001_approval_request_results', '20261103_0002_approval_request_denied', '20261109_0001_approval_request_approving']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const MINUTE = 60_000;
const ID = 'abcdefghijklmnopqrstuvwxyz';
const LINK = { bodyCid: 'sealed-body-cid', issuer: 'synthetic-requester' };
const NODE = 'https://node.example.test';
const PERMISSIONS = [{ service: 'tinycloud.kv', space: 'default', path: 'a/', actions: ['tinycloud.kv/get'] }];

const target = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string };
const resultKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
const wallet = Wallet.createRandom();

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

const service = () => new ApprovalResultService(createPrismaApprovalRequestStore(client), { apiOrigin: 'http://localhost:3001', retentionSeconds: 600, now: () => clock });
const advance = (ms: number) => { clock = new Date(clock.getTime() + ms); };
const row = () => client.approvalRequest.findUniqueOrThrow({ where: { id: ID } });

async function registered(expiresInMs: number) {
  await createPrismaApprovalRequestStore(client).register({
    id: ID, bodyCid: LINK.bodyCid, issuer: LINK.issuer,
    request: {
      targetDid: 'synthetic-requester', targetPublicJwk: target, nodeOrigin: NODE, permissions: PERMISSIONS,
      grantLifetimeSeconds: 3600, resultEncryptionPublicJwk: resultKey,
    } as unknown as ApprovalRequestRecord['request'],
    expiresAt: new Date(clock.getTime() + expiresInMs), createdAt: clock,
    resultRef: null, encryptedResult: null, resultExpiresAt: null,
  });
}

/** The signed delegation a completion handler hands to the service, valid at the admission time. */
async function delegation() {
  const sessionDid = strictSessionDid(target);
  const siwe = new SiweMessage({
    domain: 'openkey.so', address: wallet.address, statement: 'Delegate', uri: sessionDid, version: '1', chainId: 1,
    nonce: 'abcdefgh12345678', issuedAt: clock.toISOString(), expirationTime: new Date(clock.getTime() + 30 * MINUTE).toISOString(),
  }).prepareMessage();
  const signature = await wallet.signMessage(siwe);
  return {
    body: { jwk: target, host: NODE, permissions: PERMISSIONS },
    delegation: { siwe, signature, ownerDid: `did:pkh:eip155:1:${wallet.address}`, verificationMethod: sessionDid, jwk: target },
  };
}

describe('saving an admitted approval through the service', () => {
  test('a request that expired while it was signed is saved', async () => {
    await registered(10_000);
    const signed = await delegation();
    const marker = await service().admit(ID);
    advance(20_000);
    await service().approve(ID, 'owner', signed.body, signed.delegation, marker);
    const saved = await row();
    expect(saved.resultRef).not.toBeNull();
    expect(saved.approvedByUserId).toBe('owner');
  });

  test('the same save without an admission is refused as expired', async () => {
    await registered(10_000);
    const signed = await delegation();
    advance(20_000);
    await expect(service().approve(ID, 'owner', signed.body, signed.delegation)).rejects.toMatchObject({ code: 'expired_request', status: 410 });
    expect((await row()).resultRef).toBeNull();
  });

  test('an admitted save still refuses a denied request and a changed binding', async () => {
    await registered(MINUTE);
    const signed = await delegation();
    const marker = await service().admit(ID);
    await expect(service().approve(ID, 'owner', { ...signed.body, host: 'https://other.example.test' }, signed.delegation, marker))
      .rejects.toMatchObject({ code: 'request_binding', status: 400 });
    expect((await row()).resultRef).toBeNull();
    await client.approvalRequest.update({ where: { id: ID }, data: { deniedAt: clock, approvingAt: null } });
    await expect(service().approve(ID, 'owner', signed.body, signed.delegation, marker)).rejects.toMatchObject({ code: 'expired_request', extra: { status: 'denied' } });
  });

  test('an attempt that takes longer than the lease is saved when nothing replaced its marker', async () => {
    await registered(30 * MINUTE);
    const signed = await delegation();
    const marker = await service().admit(ID);
    advance(APPROVAL_CLAIM_LEASE_MS + 1_000);
    await service().approve(ID, 'owner', signed.body, signed.delegation, marker);
    expect((await row()).resultRef).not.toBeNull();
  });

  test('after a failed attempt releases the admission, deny and a retry work at once', async () => {
    await registered(30 * MINUTE);
    const first = await service().admit(ID);
    await expect(service().deny(ID, LINK)).rejects.toMatchObject({ code: 'approval_in_progress' });
    await service().release(ID, first);
    const signed = await delegation();
    const retry = await service().admit(ID);
    await service().approve(ID, 'owner', signed.body, signed.delegation, retry);
    expect((await row()).resultRef).not.toBeNull();
    await expect(service().deny(ID, LINK)).rejects.toMatchObject({ code: 'already_approved', status: 409 });
  });
});
