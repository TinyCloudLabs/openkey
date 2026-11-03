// TC-2377 (OpenKey half): an approval request the owner refuses is DENIED, a terminal state the requester
// can read. Its discover answer is HTTP 410 with the existing `expired_request` code (old clients already
// treat that as terminal and drop their keys) plus the additive `status: "denied"` and `deniedAt`.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { ApprovalResultService, type ApprovalRequestRecord } from '../services/approval-results';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import { mockModules, replaceModules } from './mock-module';
import type { approvalRequestRouter } from '../routes/approval-requests';

const MIGRATIONS = ['20261028_0001_approval_request_results', '20261103_0002_approval_request_denied']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const ORIGIN = process.env.BETTER_AUTH_URL ?? 'http://localhost:3001';
const MINUTE = 60_000;
const pair = generateKeyPairSync('ed25519');
const jwk = pair.publicKey.export({ format: 'jwk' });
const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');
const ID = 'abcdefghijklmnopqrstuvwxyz';
const BODY_CID = 'sealed-body-cid';
const RESULT_PATH = `/api/approval-requests/${ID}/result`;

let database: PGlite;
let client: PrismaClient;
let clock = new Date('2026-11-03T12:00:00Z');
let route: typeof approvalRequestRouter;

// The route opens the default database and loads Better Auth at import: replace both first.
replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      if (c.req.header('x-test-session') !== 'owner') return c.json({ error: 'Authentication required' }, 401);
      await next();
    }),
  }),
});
await mockModules({ '@openkey/db': () => ({ createPrismaClient: () => client }) });

beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  for (const migration of MIGRATIONS) await database.exec(await readFile(migration, 'utf8'));
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  // Static import cannot work: the route captures the database client when it loads.
  ({ approvalRequestRouter: route } = await import('../routes/approval-requests?approval-denied-test' as string));
});
afterAll(async () => {
  await client.$disconnect();
  await database.close();
});
beforeEach(async () => {
  await client.approvalRequest.deleteMany();
  clock = new Date('2026-11-03T12:00:00Z');
});

const store = () => createPrismaApprovalRequestStore(client);
const service = () => new ApprovalResultService(store(), { apiOrigin: ORIGIN, retentionSeconds: 600, now: () => clock });

async function registered(expiresInMs = 30 * MINUTE) {
  return store().register({
    id: ID, bodyCid: BODY_CID, issuer: 'synthetic-requester',
    request: { targetDid: 'synthetic-requester', targetPublicJwk: jwk } as unknown as ApprovalRequestRecord['request'],
    expiresAt: new Date(clock.getTime() + expiresInMs), createdAt: clock,
    resultRef: null, encryptedResult: null, resultExpiresAt: null,
  });
}

function proof(path = RESULT_PATH, key = pair.privateKey) {
  const head = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: jkt, typ: 'openkey-session-proof+jwt' })).toString('base64url');
  const credential = JSON.stringify(['discover', ID, BODY_CID, '', '']);
  const claims = Buffer.from(JSON.stringify({
    client_id: 'openkey-approval-result-v1', cred_hash: createHash('sha256').update(credential).digest('base64url'),
    htm: 'POST', htu: ORIGIN + path, iat: Math.floor(clock.getTime() / 1000), jti: `jti-${Math.random()}-0000000`,
  })).toString('base64url');
  return `${head}.${claims}.${sign(null, Buffer.from(`${head}.${claims}`), key).toString('base64url')}`;
}
const discover = (key = pair.privateKey) => service().discover(ID, { bodyCid: BODY_CID }, proof(RESULT_PATH, key));
const approve = (now = clock) => store().approve(ID, {
  resultRef: 'synthetic-result-reference', approvedByUserId: 'owner', ownerDid: 'did:pkh:eip155:1:0x1',
  encryptedResult: '{"ciphertext":"opaque"}', delegationExpiresAt: new Date(now.getTime() + 60 * MINUTE),
  resultExpiresAt: new Date(now.getTime() + 10 * MINUTE),
}, now);

describe('denying an approval request', () => {
  test('the requester then reads a terminal answer: 410 expired_request, status denied, and when', async () => {
    await registered();
    expect(await discover()).toEqual({ status: 'pending' });
    await service().deny(ID);
    await expect(discover()).rejects.toMatchObject({
      code: 'expired_request', status: 410, extra: { status: 'denied', deniedAt: clock.toISOString() },
    });
  });

  test('the answer does not change when the request would have expired anyway', async () => {
    await registered(5 * MINUTE);
    await service().deny(ID);
    clock = new Date(clock.getTime() + 10 * MINUTE);
    await expect(discover()).rejects.toMatchObject({ code: 'expired_request', extra: { status: 'denied' } });
  });

  test('a caller without the requester key learns nothing about the denial', async () => {
    await registered();
    await service().deny(ID);
    await expect(discover(generateKeyPairSync('ed25519').privateKey)).rejects.toMatchObject({ code: 'invalid_proof', status: 401 });
  });

  test('denying twice is fine and keeps the first time', async () => {
    await registered();
    await service().deny(ID);
    const first = (await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).deniedAt;
    clock = new Date(clock.getTime() + MINUTE);
    await expect(service().deny(ID)).resolves.toEqual({ status: 'denied' });
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).deniedAt).toEqual(first);
  });

  test('an approved request cannot be denied, and its result stays retrievable', async () => {
    await registered();
    expect(await approve()).toBe(true);
    await expect(service().deny(ID)).rejects.toMatchObject({ code: 'already_approved', status: 409 });
    expect(await discover()).toMatchObject({ status: 'approved', resultRef: 'synthetic-result-reference' });
  });

  test('an unknown request is not found, and an expired one is reported expired, not denied', async () => {
    await expect(service().deny(ID)).rejects.toMatchObject({ code: 'not_found', status: 404 });
    await registered(MINUTE);
    clock = new Date(clock.getTime() + 2 * MINUTE);
    await expect(service().deny(ID)).rejects.toMatchObject({ code: 'expired_request', status: 410 });
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).deniedAt).toBeNull();
  });
});

describe('a denied request is never approved', () => {
  test('the store refuses to approve it', async () => {
    await registered();
    await service().deny(ID);
    expect(await approve()).toBe(false);
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).resultRef).toBeNull();
  });

  test('the signing path refuses it before anything is signed', async () => {
    await registered();
    await service().deny(ID);
    const request = { jwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, host: undefined, permissions: undefined };
    await expect(service().assertDelegationWindow(ID, request)).rejects.toMatchObject({ code: 'expired_request', status: 410, extra: { status: 'denied' } });
  });

  test('of a concurrent approve and deny exactly one wins, and the row stays consistent', async () => {
    for (let round = 0; round < 10; round++) {
      await client.approvalRequest.deleteMany();
      await registered();
      const [approved, denied] = await Promise.all([approve(), store().deny(ID, clock)]);
      expect([approved, denied].filter(Boolean)).toHaveLength(1);
      const row = await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } });
      expect(Boolean(row.resultRef) !== Boolean(row.deniedAt)).toBe(true);
    }
  });

  test('the database itself refuses a row that is both approved and denied', async () => {
    await registered();
    await approve();
    await expect((async () => client.approvalRequest.update({ where: { id: ID }, data: { deniedAt: clock } }))()).rejects.toThrow();
  });
});

describe('POST /api/approval-requests/:id/deny', () => {
  const deny = (headers: Record<string, string> = {}) =>
    route.request(`/approval-requests/${ID}/deny`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: '{}' });
  // The route reads the real clock, so its proofs and deadlines are made on it.
  beforeEach(() => { clock = new Date(); });

  test('needs a signed-in owner', async () => {
    await registered();
    expect((await deny()).status).toBe(401);
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).deniedAt).toBeNull();
  });

  test('an owner denies, and the requester\'s next poll over HTTP carries the typed answer', async () => {
    await registered();
    const denied = await deny({ 'x-test-session': 'owner' });
    expect(denied.status).toBe(200);
    expect(await denied.json()).toEqual({ status: 'denied' });
    const polled = await route.request(RESULT_PATH.replace('/api', ''), {
      method: 'POST', headers: { 'content-type': 'application/json', 'OpenKey-Session-Proof': proof() }, body: JSON.stringify({ bodyCid: BODY_CID }),
    });
    expect(polled.status).toBe(410);
    expect(polled.headers.get('cache-control')).toBe('no-store');
    const body: Record<string, unknown> = await polled.json();
    expect(body).toEqual({ error: 'Approval request was denied', code: 'expired_request', status: 'denied', deniedAt: body.deniedAt });
    expect(Math.abs(Date.parse(String(body.deniedAt)) - Date.now())).toBeLessThan(10_000);
  });

  test('an approved request answers 409 already_approved', async () => {
    await registered();
    await approve();
    const refused = await deny({ 'x-test-session': 'owner' });
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ code: 'already_approved' });
  });
});
