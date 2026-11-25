// An approval request may name its requester with a top-level `requesterDid`. The requester is the key that
// signs the link header; the grant audience (`targetDid`, `targetPublicJwk`) may be a different, fresh key.
// /load passes the header issuer to the parser, stores the parsed request, and serves it with the field intact.
// A request without the field keeps the rule that the issuer is the target key.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { signerFromJwk } from '@tinycloud/share-envelope/links';
import { mockModules } from './mock-module';
import type { approvalRequestRouter } from '../routes/approval-requests';

const MIGRATIONS = ['20261028_0001_approval_request_results', '20261103_0002_approval_request_denied', '20261109_0001_approval_request_approving', '20261113_0001_approval_request_renewal']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const BODY_CID = `bafkrei${'a'.repeat(52)}`;
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz';
const idFor = (n: number) => `${ALPHABET.slice(0, 25)}${ALPHABET[n]}`;
const referenceFor = (id: string) => `/a/${id}#v=4&k=${'A'.repeat(43)}&c=${BODY_CID}`;

function newKey() {
  const pair = generateKeyPairSync('ed25519');
  const publicJwk = pair.publicKey.export({ format: 'jwk' });
  const signer = signerFromJwk(pair.privateKey.export({ format: 'jwk' }) as { kty: 'OKP'; crv: 'Ed25519'; x: string; d: string });
  return { did: signer.did, jwk: { kty: 'OKP' as const, crv: 'Ed25519' as const, x: publicJwk.x as string } };
}

// The requester signs the link. The target is the fresh key the grant is addressed to.
const requester = newKey();
const target = newKey();
const stranger = newKey();
const relay = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
const relayJwk = await crypto.subtle.exportKey('jwk', relay.publicKey);

const common = {
  requestVersion: 1,
  nodeOrigin: 'https://node.example.test',
  permissions: [{ service: 'tinycloud.capabilities', space: 'synthetic', path: '', actions: ['tinycloud.capabilities/read'] }],
  grantLifetimeSeconds: 3600,
  resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x, y: relayJwk.y },
};
// Today's shape: one key is both requester and grant audience.
const legacy = { ...common, issuer: requester.did, targetDid: requester.did, targetPublicJwk: requester.jwk };
// The requester signs; the grant audience is a different key.
const named = { ...common, issuer: requester.did, requesterDid: requester.did, targetDid: target.did, targetPublicJwk: target.jwk };

const served = new Map<string, { value: unknown; headerIssuer: string }>();
const serve = (n: number, value: unknown, headerIssuer = requester.did) => {
  const id = idFor(n);
  served.set(id, { value, headerIssuer });
  return id;
};

let database: PGlite;
let client: PrismaClient;
let route: typeof approvalRequestRouter;

// The links service is the network; it answers with the request registered for the id. parseLink and
// parseApprovalRequest stay real.
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => client }),
  '@tinycloud/share-envelope/links': () => ({
    resolveLink: async (link: string) => {
      const entry = served.get(new URL(link).pathname.split('/').at(-1)!)!;
      return {
        type: 'openkey-approval-request',
        header: { bodyCid: BODY_CID, issuer: entry.headerIssuer, expiresAt: new Date(Date.now() + 3600_000).toISOString() },
        value: entry.value,
      };
    },
  }),
});

beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  for (const migration of MIGRATIONS) await database.exec(await readFile(migration, 'utf8'));
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  // Static import cannot work: the route captures the database client when it loads.
  ({ approvalRequestRouter: route } = await import('../routes/approval-requests?approval-requester-did-test' as string));
});
afterAll(async () => {
  await client.$disconnect();
  await database.close();
});
beforeEach(async () => {
  served.clear();
  await client.approvalRequest.deleteMany();
});

const load = (id: string) =>
  route.request(`/approval-requests/${id}/load`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reference: referenceFor(id) }),
  });

describe.serial('/load with a requesterDid on the approval request', () => {
  test('a request signed by its requester for a different target key loads with requesterDid intact', async () => {
    const id = serve(0, named);
    const response = await load(id);
    expect(response.status).toBe(200);
    const body: { request: Record<string, unknown> } = await response.json();
    expect(body.request).toEqual(named);
    expect(body.request.requesterDid).toBe(requester.did);
    expect(body.request.targetDid).toBe(target.did);
    const stored = await client.approvalRequest.findUniqueOrThrow({ where: { id } });
    expect(stored.issuer).toBe(requester.did);
    expect(stored.request).toEqual(named);
  });

  test('a second load of the same link serves the same request', async () => {
    const id = serve(1, named);
    await load(id);
    const again = await load(id);
    expect(again.status).toBe(200);
    const reloaded: { request: unknown } = await again.json();
    expect(reloaded.request).toEqual(named);
  });

  test('a request whose body issuer differs from the link header issuer is refused and not stored', async () => {
    const id = serve(2, { ...named, issuer: stranger.did, requesterDid: stranger.did });
    const response = await load(id);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'issuer_binding_mismatch' });
    expect(await client.approvalRequest.findUnique({ where: { id } })).toBeNull();
  });

  test('a requesterDid that differs from the body issuer is refused and not stored', async () => {
    const id = serve(3, { ...named, requesterDid: stranger.did });
    const response = await load(id);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'issuer_binding_mismatch' });
    expect(await client.approvalRequest.findUnique({ where: { id } })).toBeNull();
  });

  test('a requesterDid equal to the target DID is refused and not stored', async () => {
    const id = serve(4, { ...legacy, requesterDid: requester.did });
    const response = await load(id);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'issuer_binding_mismatch' });
    expect(await client.approvalRequest.findUnique({ where: { id } })).toBeNull();
  });

  test('a target public key that does not match the target DID is refused', async () => {
    const id = serve(5, { ...named, targetPublicJwk: stranger.jwk });
    const response = await load(id);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'issuer_binding_mismatch' });
    expect(await client.approvalRequest.findUnique({ where: { id } })).toBeNull();
  });

  test('a requesterDid of the wrong JSON type is refused and not stored', async () => {
    const id = serve(6, { ...named, requesterDid: 5 });
    const response = await load(id);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'body_validation_failed' });
    expect(await client.approvalRequest.findUnique({ where: { id } })).toBeNull();
  });
});

describe.serial('/load without a requesterDid', () => {
  test('a request whose issuer is its target key loads and is served with no requesterDid member', async () => {
    const id = serve(7, legacy);
    const response = await load(id);
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).not.toContain('requesterDid');
    const body: { request: unknown } = JSON.parse(text);
    expect(body.request).toEqual(legacy);
    const stored = await client.approvalRequest.findUniqueOrThrow({ where: { id } });
    expect(stored.request).toEqual(legacy);
    expect(JSON.stringify(stored.request)).not.toContain('requesterDid');
  });

  test('a request whose issuer is not its target DID is refused', async () => {
    const id = serve(8, { ...legacy, targetDid: target.did, targetPublicJwk: target.jwk });
    const response = await load(id);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'issuer_binding_mismatch' });
    expect(await client.approvalRequest.findUnique({ where: { id } })).toBeNull();
  });

  test('a target public key that does not match the target DID is refused', async () => {
    const id = serve(10, { ...legacy, targetPublicJwk: stranger.jwk });
    const response = await load(id);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'issuer_binding_mismatch' });
    expect(await client.approvalRequest.findUnique({ where: { id } })).toBeNull();
  });

  test('a request signed by a key other than its issuer is refused', async () => {
    const id = serve(9, legacy, stranger.did);
    const response = await load(id);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'issuer_binding_mismatch' });
    expect(await client.approvalRequest.findUnique({ where: { id } })).toBeNull();
  });
});
