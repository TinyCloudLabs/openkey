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
const LINK = { bodyCid: BODY_CID, issuer: 'synthetic-requester' };
const LINK_KEY = 'A'.repeat(43);
const REFERENCE = `/a/${ID}#v=4&k=${LINK_KEY}&c=bafkrei${'a'.repeat(52)}`;
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
// The links service is the network; its answer is set per test. parseLink stays real.
let resolveLinkImpl: (link: string) => Promise<unknown> = async () => ({});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => client }),
  '@tinycloud/share-envelope/links': () => ({ resolveLink: (link: string) => resolveLinkImpl(link) }),
});

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
    await service().deny(ID, LINK);
    await expect(discover()).rejects.toMatchObject({
      code: 'expired_request', status: 410, extra: { status: 'denied', deniedAt: clock.toISOString() },
    });
  });

  test('the answer does not change when the request would have expired anyway', async () => {
    await registered(5 * MINUTE);
    await service().deny(ID, LINK);
    clock = new Date(clock.getTime() + 10 * MINUTE);
    await expect(discover()).rejects.toMatchObject({ code: 'expired_request', extra: { status: 'denied' } });
  });

  test('a caller without the requester key learns nothing about the denial', async () => {
    await registered();
    await service().deny(ID, LINK);
    await expect(discover(generateKeyPairSync('ed25519').privateKey)).rejects.toMatchObject({ code: 'invalid_proof', status: 401 });
  });

  test('denying twice is fine and keeps the first time', async () => {
    await registered();
    await service().deny(ID, LINK);
    const first = (await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).deniedAt;
    clock = new Date(clock.getTime() + MINUTE);
    await expect(service().deny(ID, LINK)).resolves.toEqual({ status: 'denied' });
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).deniedAt).toEqual(first);
  });

  test('an approved request cannot be denied, and its result stays retrievable', async () => {
    await registered();
    expect(await approve()).toBe(true);
    await expect(service().deny(ID, LINK)).rejects.toMatchObject({ code: 'already_approved', status: 409 });
    expect(await discover()).toMatchObject({ status: 'approved', resultRef: 'synthetic-result-reference' });
  });

  test('a link for a different request body or issuer cannot deny this one', async () => {
    await registered();
    await expect(service().deny(ID, { bodyCid: 'another-body-cid', issuer: LINK.issuer })).rejects.toMatchObject({ code: 'link_required', status: 403 });
    await expect(service().deny(ID, { bodyCid: BODY_CID, issuer: 'someone-else' })).rejects.toMatchObject({ code: 'link_required', status: 403 });
    expect(await discover()).toEqual({ status: 'pending' });
  });

  test('an unknown request is not found, and an expired one is reported expired, not denied', async () => {
    await expect(service().deny(ID, LINK)).rejects.toMatchObject({ code: 'not_found', status: 404 });
    await registered(MINUTE);
    clock = new Date(clock.getTime() + 2 * MINUTE);
    await expect(service().deny(ID, LINK)).rejects.toMatchObject({ code: 'expired_request', status: 410 });
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).deniedAt).toBeNull();
  });
});

describe('a denied request is never approved', () => {
  test('the store refuses to approve it', async () => {
    await registered();
    await service().deny(ID, LINK);
    expect(await approve()).toBe(false);
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).resultRef).toBeNull();
  });

  test('the signing path refuses it before anything is signed', async () => {
    await registered();
    await service().deny(ID, LINK);
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
  const SIGNED_IN = { 'x-test-session': 'owner' };
  const deny = (headers: Record<string, string> = {}, body: unknown = { reference: REFERENCE }) =>
    route.request(`/approval-requests/${ID}/deny`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  const poll = () => route.request(RESULT_PATH.replace('/api', ''), {
    method: 'POST', headers: { 'content-type': 'application/json', 'OpenKey-Session-Proof': proof() }, body: JSON.stringify({ bodyCid: BODY_CID }),
  });
  // The route reads the real clock, so its proofs and deadlines are made on it.
  beforeEach(() => { clock = new Date(); resolveLinkImpl = async () => ({ type: 'openkey-approval-request', header: LINK }); });

  test('needs a signed-in user', async () => {
    await registered();
    expect((await deny({})).status).toBe(401);
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).deniedAt).toBeNull();
  });

  test('a signed-in user who holds the complete link denies, and the requester\'s next poll carries the typed answer', async () => {
    await registered();
    const denied = await deny(SIGNED_IN);
    expect(denied.status).toBe(200);
    expect(await denied.json()).toEqual({ status: 'denied' });
    const polled = await poll();
    expect(polled.status).toBe(410);
    expect(polled.headers.get('cache-control')).toBe('no-store');
    const body: Record<string, unknown> = await polled.json();
    expect(body).toEqual({ error: 'Approval request was denied', code: 'expired_request', status: 'denied', deniedAt: body.deniedAt });
    expect(Math.abs(Date.parse(String(body.deniedAt)) - Date.now())).toBeLessThan(10_000);
  });

  test('denying again with the link is idempotent', async () => {
    await registered();
    expect((await deny(SIGNED_IN)).status).toBe(200);
    const again = await deny(SIGNED_IN);
    expect(again.status).toBe(200);
    expect(await again.json()).toEqual({ status: 'denied' });
  });

  describe('a signed-in user without the link is refused and the request stays open', () => {
    const refusals: Array<[string, () => Response | Promise<Response>]> = [
      ['no reference at all', () => deny(SIGNED_IN, {})],
      ['a body that is not JSON', () => route.request(`/approval-requests/${ID}/deny`, { method: 'POST', headers: { 'content-type': 'application/json', ...SIGNED_IN }, body: 'nope' })],
      ['the id alone, without the key fragment', () => deny(SIGNED_IN, { reference: `/a/${ID}` })],
      ['a link for another request', () => deny(SIGNED_IN, { reference: REFERENCE.replace(ID, 'zyxwvutsrqponmlkjihgfedcba') })],
      ['a link the links service cannot open (wrong key)', () => { resolveLinkImpl = async () => { throw Object.assign(new Error('x'), { code: 'decryption_failed' }); }; return deny(SIGNED_IN); }],
      ['a link that opens to a different request body', () => { resolveLinkImpl = async () => ({ type: 'openkey-approval-request', header: { ...LINK, bodyCid: 'another-body-cid' } }); return deny(SIGNED_IN); }],
      ['a link that opens to a different issuer', () => { resolveLinkImpl = async () => ({ type: 'openkey-approval-request', header: { ...LINK, issuer: 'someone-else' } }); return deny(SIGNED_IN); }],
      ['a link that opens to another kind of link', () => { resolveLinkImpl = async () => ({ type: 'tinycloud-share', header: LINK }); return deny(SIGNED_IN); }],
    ];
    test.each(refusals)('%s', async (_name, attempt) => {
      await registered();
      const refused = await attempt();
      expect(refused.status).toBe(403);
      expect(await refused.json()).toMatchObject({ code: 'link_required' });
      expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).deniedAt).toBeNull();
      expect(await (await poll()).json()).toEqual({ status: 'pending' });
    });

    test('the refusal never echoes the link or its key', async () => {
      await registered();
      resolveLinkImpl = async () => { throw Object.assign(new Error('x'), { code: 'decryption_failed' }); };
      const refused = await deny(SIGNED_IN);
      const text = await refused.text();
      expect(text).not.toContain(LINK_KEY);
      expect(text).not.toContain(REFERENCE);
    });
  });

  test('an approved request answers 409 already_approved', async () => {
    await registered();
    await approve();
    const refused = await deny(SIGNED_IN);
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ code: 'already_approved' });
  });
});
