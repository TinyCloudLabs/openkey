// Which key signs the requester proof for an approval request.
// Before a browser loads the request, the server holds only the link header, so a discover proof is checked
// against the header issuer: the requester key. After /load registers the request, discover, fetch and ack are
// checked against the request's target key. A request that names a distinct requester therefore polls with the
// requester key until it is loaded and with the target key afterwards. A request whose issuer is its target key
// has a single key throughout.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { openLinkRecord, prepareLinkRecord, signHeader, signerFromJwk } from '@tinycloud/share-envelope/links';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import { createMiddleware } from 'hono/factory';
import { mockModules, replaceModules } from './mock-module';
import type { approvalRequestRouter } from '../routes/approval-requests';

const MIGRATIONS = ['20261028_0001_approval_request_results', '20261103_0002_approval_request_denied', '20261109_0001_approval_request_approving', '20261113_0001_approval_request_renewal']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const apiOrigin = process.env.BETTER_AUTH_URL ?? 'http://localhost:3001';
const NAMED_ID = 'abcdefghijklmnopqrstuvwxya';
const SINGLE_ID = 'abcdefghijklmnopqrstuvwxyb';

type Jwk = { kty: 'OKP'; crv: 'Ed25519'; x: string };
type Party = { did: string; jwk: Jwk; privateKey: KeyObject; signer: ReturnType<typeof signerFromJwk> };

function newParty(): Party {
  const pair = generateKeyPairSync('ed25519');
  const x = String(pair.publicKey.export({ format: 'jwk' }).x);
  const signer = signerFromJwk({ kty: 'OKP', crv: 'Ed25519', x, d: String(pair.privateKey.export({ format: 'jwk' }).d) });
  return { did: signer.did, jwk: { kty: 'OKP', crv: 'Ed25519', x }, privateKey: pair.privateKey, signer };
}
const thumbprint = (jwk: Jwk) => createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');

const requester = newParty();
const target = newParty();
const stranger = newParty();
const relay = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
const relayJwk = await crypto.subtle.exportKey('jwk', relay.publicKey);
const common = {
  requestVersion: 1,
  nodeOrigin: 'https://node.example.test',
  permissions: [{ service: 'tinycloud.capabilities', space: 'synthetic', path: '', actions: ['tinycloud.capabilities/read'] }],
  grantLifetimeSeconds: 3600,
  resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x, y: relayJwk.y },
};

type Opened = Awaited<ReturnType<typeof openLinkRecord>>;
const links = new Map<string, { opened: Opened; value: unknown }>();

/** A request link signed by `signingParty`, so the header issuer is that party's DID. */
async function makeLink(id: string, signingParty: Party, request: object) {
  const sealed = await prepareLinkRecord({
    type: 'openkey-approval-request', issuerKey: signingParty.signer, apiOrigin: 'https://api.tinycloud.xyz',
    expiresAt: new Date(Date.now() + 3600_000), plaintext: new TextEncoder().encode(JSON.stringify(request)),
  });
  const opened = await openLinkRecord(sealed.record, sealed.key);
  links.set(id, { opened, value: request });
  return opened;
}

let database: PGlite;
let client: PrismaClient;
let route: typeof approvalRequestRouter;

// No route under test reads the session; the real middleware would start the auth stack.
replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (_c, next) => { await next(); }),
  }),
});
// The links service is the network; it answers with the link registered for the id. parseLink and
// parseApprovalRequest stay real.
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => client }),
  '@tinycloud/share-envelope/links': () => ({
    resolveLink: async (link: string) => {
      const entry = links.get(new URL(link).pathname.split('/').at(-1)!)!;
      return { type: 'openkey-approval-request', header: entry.opened.header, value: entry.value };
    },
  }),
});

beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  for (const migration of MIGRATIONS) await database.exec(await readFile(migration, 'utf8'));
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  // Static import cannot work: the route captures the database client when it loads.
  ({ approvalRequestRouter: route } = await import('../routes/approval-requests?approval-requester-proofs-test' as string));
});
afterAll(async () => {
  await client.$disconnect();
  await database.close();
});
beforeEach(async () => {
  await client.approvalRequest.deleteMany();
});

function proof(party: Party, action: 'discover' | 'fetch' | 'ack', path: string, id: string, bodyCid: string, ref = '', ackId = '') {
  const head = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: thumbprint(party.jwk), typ: 'openkey-session-proof+jwt' })).toString('base64url');
  const claims = Buffer.from(JSON.stringify({
    client_id: 'openkey-approval-result-v1',
    cred_hash: createHash('sha256').update(JSON.stringify([action, id, bodyCid, ref, ackId])).digest('base64url'),
    htm: 'POST', htu: `${apiOrigin}${path}`, iat: Math.floor(Date.now() / 1000), jti: randomBytes(24).toString('base64url'),
  })).toString('base64url');
  return `${head}.${claims}.${sign(null, Buffer.from(`${head}.${claims}`), party.privateKey).toString('base64url')}`;
}

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  route.request(path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
const reply = async (response: Response) => ({ status: response.status, body: await response.json() });

/** A poll before the request is loaded: the unsaved request is known only by its signed link header. */
async function preLoadPoll(id: string, opened: Opened, signingParty: Party, proofParty: Party) {
  return reply(await post(`/approval-requests/${id}/result`, {
    bodyCid: opened.header.bodyCid, header: opened.header, signature: await signHeader(opened.header, signingParty.signer),
  }, { 'OpenKey-Session-Proof': proof(proofParty, 'discover', `/api/approval-requests/${id}/result`, id, opened.header.bodyCid) }));
}
const discover = async (id: string, bodyCid: string, proofParty: Party) =>
  reply(await post(`/approval-requests/${id}/result`, { bodyCid },
    { 'OpenKey-Session-Proof': proof(proofParty, 'discover', `/api/approval-requests/${id}/result`, id, bodyCid) }));
const load = (id: string, bodyCid: string) =>
  post(`/approval-requests/${id}/load`, { reference: `/a/${id}#v=4&k=${'A'.repeat(43)}&c=${bodyCid}` });
const fetchResult = async (ref: string, id: string, bodyCid: string, proofParty: Party) =>
  reply(await post(`/approval-results/${ref}/fetch`, { requestId: id, bodyCid },
    { 'OpenKey-Session-Proof': proof(proofParty, 'fetch', `/api/approval-results/${ref}/fetch`, id, bodyCid, ref) }));
const acknowledge = async (ref: string, id: string, bodyCid: string, ackId: string, proofParty: Party) =>
  reply(await post(`/approval-results/${ref}/ack`, { requestId: id, bodyCid, ackId },
    { 'OpenKey-Session-Proof': proof(proofParty, 'ack', `/api/approval-results/${ref}/ack`, id, bodyCid, ref, ackId) }));
const INVALID_PROOF = { status: 401, body: { error: 'Requester proof is invalid', code: 'invalid_proof' } };
const PENDING = { status: 202, body: { status: 'pending' } };

describe.serial('a request that names a distinct requester', () => {
  const named = { ...common, issuer: requester.did, requesterDid: requester.did, targetDid: target.did, targetPublicJwk: target.jwk };

  test('before load, a proof signed by the requester key is pending and nothing is recorded', async () => {
    const opened = await makeLink(NAMED_ID, requester, named);
    expect(opened.header.issuer).toBe(requester.did);
    expect(await preLoadPoll(NAMED_ID, opened, requester, requester)).toEqual(PENDING);
    expect(await client.approvalRequest.count()).toBe(0);
  });

  test('before load, a proof signed by the target key is refused', async () => {
    const opened = await makeLink(NAMED_ID, requester, named);
    expect(await preLoadPoll(NAMED_ID, opened, requester, target)).toEqual(INVALID_PROOF);
    expect(await client.approvalRequest.count()).toBe(0);
  });

  test('after load, only the target key can poll, fetch and acknowledge; the requester key is refused on each', async () => {
    const opened = await makeLink(NAMED_ID, requester, named);
    const bodyCid = opened.header.bodyCid;
    expect((await load(NAMED_ID, bodyCid)).status).toBe(200);
    const loaded = await client.approvalRequest.findUniqueOrThrow({ where: { id: NAMED_ID } });

    // The first poll after load, still signed by the requester key.
    expect(await discover(NAMED_ID, bodyCid, requester)).toEqual(INVALID_PROOF);
    expect(await discover(NAMED_ID, bodyCid, stranger)).toEqual(INVALID_PROOF);
    expect(await discover(NAMED_ID, bodyCid, target)).toEqual(PENDING);
    expect(await client.approvalRequest.findUniqueOrThrow({ where: { id: NAMED_ID } })).toEqual(loaded);

    const resultRef = 'synthetic-result-reference';
    const approved = await createPrismaApprovalRequestStore(client).approve(NAMED_ID, {
      resultRef, approvedByUserId: 'owner', ownerDid: 'did:pkh:eip155:1:0x1',
      encryptedResult: '{}', delegationExpiresAt: new Date(Date.now() + 3600_000), resultExpiresAt: new Date(Date.now() + 600_000),
    }, new Date());
    expect(approved).toBe(true);

    const ackId = 'durable-requester-proofs-ack-0001';
    expect(await discover(NAMED_ID, bodyCid, requester)).toEqual(INVALID_PROOF);
    expect(await fetchResult(resultRef, NAMED_ID, bodyCid, requester)).toEqual(INVALID_PROOF);
    expect(await acknowledge(resultRef, NAMED_ID, bodyCid, ackId, requester)).toEqual(INVALID_PROOF);
    expect((await client.approvalRequest.findUniqueOrThrow({ where: { id: NAMED_ID } })).ackId).toBeNull();

    expect(await discover(NAMED_ID, bodyCid, target)).toMatchObject({ status: 200, body: { status: 'approved', resultRef } });
    expect(await fetchResult(resultRef, NAMED_ID, bodyCid, target)).toMatchObject({ status: 200, body: { requestId: NAMED_ID, bodyCid, resultRef } });
    expect(await acknowledge(resultRef, NAMED_ID, bodyCid, ackId, target)).toEqual({ status: 200, body: { ackId, status: 'acknowledged' } });
  });
});

describe.serial('a request without a requesterDid', () => {
  const legacy = { ...common, issuer: requester.did, targetDid: requester.did, targetPublicJwk: requester.jwk };

  test('the issuer key is the target key, so one key signs before and after load', async () => {
    const opened = await makeLink(SINGLE_ID, requester, legacy);
    const bodyCid = opened.header.bodyCid;
    expect(await preLoadPoll(SINGLE_ID, opened, requester, requester)).toEqual(PENDING);
    expect(await preLoadPoll(SINGLE_ID, opened, requester, stranger)).toEqual(INVALID_PROOF);
    expect(await client.approvalRequest.count()).toBe(0);

    expect((await load(SINGLE_ID, bodyCid)).status).toBe(200);
    expect(await discover(SINGLE_ID, bodyCid, requester)).toEqual(PENDING);
    expect(await discover(SINGLE_ID, bodyCid, stranger)).toEqual(INVALID_PROOF);
  });
});
