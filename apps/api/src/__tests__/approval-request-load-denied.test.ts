// TC-2459: /load tells the review page whether the request was declined, so a reopened declined link can say
// "Declined" instead of showing the open review card. The field is additive: `approved` and every other field
// keep their meaning, so a page that does not know `denied` behaves as before.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { parseApprovalRequest, signerFromJwk } from '@tinycloud/share-envelope/links';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import { mockModules, replaceModules } from './mock-module';
import type { approvalRequestRouter } from '../routes/approval-requests';

const MIGRATIONS = ['20261028_0001_approval_request_results', '20261103_0002_approval_request_denied']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const ID = 'abcdefghijklmnopqrstuvwxyz';
const REFERENCE = `/a/${ID}#v=4&k=${'A'.repeat(43)}&c=bafkrei${'a'.repeat(52)}`;
const BODY_CID = `bafkrei${'a'.repeat(52)}`;

const pair = generateKeyPairSync('ed25519');
const publicJwk = pair.publicKey.export({ format: 'jwk' });
const signer = signerFromJwk(pair.privateKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string; d: string });
const relay = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
const relayJwk = await crypto.subtle.exportKey('jwk', relay.publicKey);
const request = parseApprovalRequest({
  issuer: signer.did, requestVersion: 1, targetDid: signer.did,
  targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: publicJwk.x },
  nodeOrigin: 'https://node.example.test',
  permissions: [{ service: 'tinycloud.capabilities', space: 'synthetic', path: '', actions: ['tinycloud.capabilities/read'] }],
  grantLifetimeSeconds: 3600,
  resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x, y: relayJwk.y },
});
const HEADER = { bodyCid: BODY_CID, issuer: signer.did, expiresAt: new Date(Date.now() + 3600_000).toISOString() };

let database: PGlite;
let client: PrismaClient;
let route: typeof approvalRequestRouter;

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      if (c.req.header('x-test-session') !== 'owner') return c.json({ error: 'Authentication required' }, 401);
      await next();
    }),
  }),
});
// The links service is the network; it answers with this request. parseLink stays real.
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => client }),
  '@tinycloud/share-envelope/links': () => ({
    resolveLink: async () => ({ type: 'openkey-approval-request', header: HEADER, value: request }),
  }),
});

beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  for (const migration of MIGRATIONS) await database.exec(await readFile(migration, 'utf8'));
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  // Static import cannot work: the route captures the database client when it loads.
  ({ approvalRequestRouter: route } = await import('../routes/approval-requests?approval-load-denied-test' as string));
});
afterAll(async () => {
  await client.$disconnect();
  await database.close();
});
beforeEach(async () => {
  await client.approvalRequest.deleteMany();
});

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  route.request(path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
const load = async () => {
  const response = await post(`/approval-requests/${ID}/load`, { reference: REFERENCE });
  expect(response.status).toBe(200);
  return await response.json() as Record<string, unknown>;
};
const decline = () => post(`/approval-requests/${ID}/deny`, { reference: REFERENCE }, { 'x-test-session': 'owner' });

describe('/load reports whether the request was declined', () => {
  test('an open request is not denied, and the fields the page already reads are unchanged', async () => {
    const body = await load();
    expect(body).toMatchObject({ denied: false, approved: false, requestId: ID, bodyCid: BODY_CID });
    expect(body.request).toEqual(request);
    expect(typeof body.expiresAt).toBe('string');
  });

  test('after the owner declines, reopening the same link says denied', async () => {
    await load();
    expect((await decline()).status).toBe(200);
    expect(await load()).toMatchObject({ denied: true, approved: false });
  });

  test('a decline is not undone by loading the link again, as often as it is opened', async () => {
    await load();
    await decline();
    for (let round = 0; round < 3; round++) expect(await load()).toMatchObject({ denied: true });
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: ID } })).deniedAt).not.toBeNull();
  });

  test('an approved request stays approved and is not denied', async () => {
    await load();
    const approved = await createPrismaApprovalRequestStore(client).approve(ID, {
      resultRef: 'synthetic-result-reference', approvedByUserId: 'owner', ownerDid: 'did:pkh:eip155:1:0x1',
      encryptedResult: '{}', delegationExpiresAt: new Date(Date.now() + 3600_000), resultExpiresAt: new Date(Date.now() + 600_000),
    }, new Date());
    expect(approved).toBe(true);
    expect(await load()).toMatchObject({ approved: true, denied: false });
  });
});
