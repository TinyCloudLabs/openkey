import { afterAll, beforeAll, expect, setSystemTime, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { Wallet } from 'ethers';
import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';
import type { SessionContext } from '../middleware/session';
import { createPrismaApprovalRequestStore } from '../services/approval-request-store';
import type { ApprovalRequestRecord } from '../services/approval-results';
import { createRenewalLeaseRouter } from '../routes/renewal-leases';
import { mockModules, replaceModules } from './mock-module';

const API_ORIGIN = process.env.BETTER_AUTH_URL ?? 'http://localhost:3001';
const BROWSER_ORIGIN = 'http://localhost:5173';
const NODE = 'https://node.tinycloud.xyz';
const OWNER_ID = 'lease-status-owner';
const owner = Wallet.createRandom();
const ownerDid = `did:pkh:eip155:1:${owner.address}`;
const dayMs = 86_400_000;
let database: PGlite;
let client: PrismaClient;
let app: Hono;

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c) => c.json({ error: 'Authentication required' }, 401)),
  }),
});
await mockModules({ '@openkey/db': () => ({ createPrismaClient: () => client }) });

beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  const migrations = new URL('../../../../packages/db/prisma/migrations/', import.meta.url);
  const entries = await readdir(migrations, { withFileTypes: true });
  for (const name of entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort()) {
    await database.exec(await readFile(new URL(`${name}/migration.sql`, migrations), 'utf8'));
  }
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  await client.user.create({ data: { id: OWNER_ID, email: 'owner@example.test' } });
  await client.ethereumKey.create({
    data: { userId: OWNER_ID, address: owner.address, publicKey: owner.signingKey.publicKey, sealedBlob: 'sealed' },
  });

  const { approvalRequestRouter } = await import('../routes/approval-requests?approval-lease-status-test' as string);
  const stop = new Hono<SessionContext>();
  stop.use('*', async (c, next) => {
    c.set('user', await client.user.findUniqueOrThrow({ where: { id: OWNER_ID } }) as SessionContext['Variables']['user']);
    await next();
  });
  stop.route('/', createRenewalLeaseRouter(client, {
    now: () => new Date(),
    signManaged: (_key, _sealed, message) => owner.signMessage(message),
    fetch: Object.assign(async (url: Parameters<typeof fetch>[0]) => {
      expect(url).toBe(`${NODE}/revoke`);
      return new Response(null, { status: 204 });
    }, { preconnect: fetch.preconnect }),
    open: async (text) => text,
    seal: async (text) => text,
  }));
  app = new Hono();
  app.route('/api', approvalRequestRouter);
  app.route('/api/account/renewal-leases', stop);
}, 30_000);

afterAll(async () => {
  await client?.$disconnect();
  await database?.close();
});

const hash = (value: string) => createHash('sha256').update(value).digest('base64url');

async function fixture(id: string, state: 'leased' | 'expired' | 'finite' | 'pending' = 'leased', pair = generateKeyPairSync('ed25519')) {
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const keyId = hash(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x }));
  const bodyCid = `body-${id}`;
  const originalCid = state === 'pending' ? null : `grant-${id}`;
  const body = { bodyCid, originalCid };
  const leaseCid = `lease-${id}`;
  const now = new Date();
  const windowEnd = new Date(now.getTime() + 7 * dayMs);
  const leaseExpiresAt = new Date(now.getTime() + (state === 'expired' ? -dayMs : 90 * dayMs));
  const store = createPrismaApprovalRequestStore(client);
  await store.register({
    id, bodyCid, issuer: 'test-requester', request: { targetPublicJwk: jwk } as ApprovalRequestRecord['request'],
    createdAt: now, expiresAt: new Date(now.getTime() + dayMs),
    resultRef: null, resultExpiresAt: null, encryptedResult: null,
  });
  if (state !== 'pending') {
    const lease = state === 'finite' ? undefined : {
      leaseCid, approvalRequestId: id, userId: OWNER_ID, sessionId: null, ownerDid, originalCid: originalCid!,
      nodeOrigin: NODE, nodeDid: 'test-node', renewerDid: 'test-renewer', leaseLifetimeSeconds: 90 * 86_400,
      approvedAt: now, leaseExpiresAt,
    };
    if (lease) await client.renewalLease.create({ data: { ...lease, grantSiwe: 'signed grant message' } });
    expect(await store.approve(id, {
      resultRef: `result-${id}`, approvedByUserId: OWNER_ID, ownerDid, encryptedResult: '{}',
      delegationExpiresAt: windowEnd, resultExpiresAt: new Date(now.getTime() + 600_000), lease,
    }, now)).toBe(true);
  }

  const statusPath = `/api/approval-requests/${id}/lease-status`;
  const resultPath = `/api/approval-requests/${id}/result`;
  function proof(action = 'lease-status', path = statusPath, cid = originalCid, iat = Math.floor(Date.now() / 1000)) {
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: keyId, typ: 'openkey-session-proof+jwt' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      client_id: 'openkey-approval-result-v1',
      cred_hash: hash(JSON.stringify([action, id, bodyCid, action === 'discover' ? '' : cid ?? '', ''])),
      htm: 'POST', htu: API_ORIGIN + path, iat, jti: randomUUID(),
    })).toString('base64url');
    const signed = `${header}.${payload}`;
    return `${signed}.${sign(null, Buffer.from(signed), pair.privateKey).toString('base64url')}`;
  }
  return { body, id, leaseCid, leaseExpiresAt, proof, resultPath, statusPath, windowEnd };
}

function post(path: string, body: unknown, proof?: string) {
  return app.request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(proof === undefined ? {} : { 'OpenKey-Session-Proof': proof }) },
    body: JSON.stringify(body),
  });
}

test('the requester reads an active lease without an owner session, even after result collection ends', async () => {
  const f = await fixture('a'.repeat(26));
  await client.approvalRequest.update({
    where: { id: f.id },
    data: { ackId: 'saved-ack', acknowledgedAt: new Date(), resultExpiresAt: new Date(0), encryptedResult: null },
  });
  const response = await post(f.statusPath, f.body, f.proof());
  expect(response.status).toBe(200);
  expect(response.headers.get('Cache-Control')).toBe('no-store');
  expect(await response.json()).toEqual({
    leaseState: 'active', originalCid: f.body.originalCid,
    windowEnd: f.windowEnd.toISOString(), leaseExpiresAt: f.leaseExpiresAt.toISOString(),
  });
});

test('the requester sees stopped after the owner stops the lease in Settings', async () => {
  const f = await fixture('b'.repeat(26));
  const stop = await app.request(`/api/account/renewal-leases/${f.leaseCid}/stop`, {
    method: 'POST', headers: { Origin: BROWSER_ORIGIN },
  });
  expect(stop.status).toBe(200);
  expect(await stop.json()).toEqual({ stopped: true });
  const { revokedAt } = await client.renewalLease.findUniqueOrThrow({ where: { leaseCid: f.leaseCid } });
  expect(revokedAt).toBeInstanceOf(Date);
  const response = await post(f.statusPath, f.body, f.proof());
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({
    leaseState: 'stopped', originalCid: f.body.originalCid, stoppedAt: revokedAt!.toISOString(),
    windowEnd: f.windowEnd.toISOString(), leaseExpiresAt: f.leaseExpiresAt.toISOString(),
  });
});

test('the requester sees expired after the lease reaches its end', async () => {
  const f = await fixture('c'.repeat(26), 'expired');
  const response = await post(f.statusPath, f.body, f.proof());
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({
    leaseState: 'expired', originalCid: f.body.originalCid,
    windowEnd: f.windowEnd.toISOString(), leaseExpiresAt: f.leaseExpiresAt.toISOString(),
  });
});

test.each([
  ['finite', 'd'.repeat(26)],
  ['pending', 'e'.repeat(26)],
] as const)('the requester sees none when the request is %s (%s)', async (state, id) => {
  const f = await fixture(id, state);
  const response = await post(f.statusPath, f.body, f.proof());
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ leaseState: 'none', originalCid: null });
});

test('result and lease status proofs cannot be used across actions', async () => {
  const f = await fixture('f'.repeat(26));
  const resultProof = f.proof('discover', f.resultPath);
  const statusProof = f.proof();
  expect((await post(f.statusPath, f.body, resultProof)).status).toBe(401);
  expect((await post(f.resultPath, f.body, statusProof)).status).toBe(401);
  expect((await post(f.statusPath, f.body, f.proof('discover'))).status).toBe(401);
  expect((await post(f.resultPath, f.body, f.proof('lease-status', f.resultPath))).status).toBe(401);
  expect((await post(f.resultPath, f.body, resultProof)).status).toBe(200);
  expect((await post(f.statusPath, f.body, statusProof)).status).toBe(200);
});

test('a repeated lease status proof is rejected', async () => {
  const f = await fixture('g'.repeat(26));
  const proof = f.proof();
  expect((await post(f.statusPath, f.body, proof)).status).toBe(200);
  const replay = await post(f.statusPath, f.body, proof);
  expect(replay.status).toBe(401);
  expect(await replay.json()).toEqual({ error: 'Requester proof is invalid', code: 'invalid_proof' });
});

test('a different requester receives the same 404 as for an unknown request', async () => {
  const caller = await fixture('h'.repeat(26));
  const other = await fixture('i'.repeat(26));
  const unknown = '/api/approval-requests/jjjjjjjjjjjjjjjjjjjjjjjjjj/lease-status';
  const responses = await Promise.all([
    post(other.statusPath, other.body, caller.proof()),
    post(unknown, other.body, caller.proof()),
    post(caller.statusPath, other.body, caller.proof()),
  ]);
  for (const response of responses) {
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: 'Saved approval request not found', code: 'not_found' });
  }
});

test('a proof is specific to its request even when both requests use the same key', async () => {
  const pair = generateKeyPairSync('ed25519');
  const first = await fixture('n'.repeat(26), 'pending', pair);
  const second = await fixture('o'.repeat(26), 'pending', pair);
  const proof = first.proof('lease-status', second.statusPath);
  expect((await post(second.statusPath, second.body, proof)).status).toBe(401);
  expect((await post(second.statusPath, second.body, second.proof())).status).toBe(200);
});

test('the requester must sign and supply the original approved grant CID', async () => {
  const f = await fixture('k'.repeat(26));
  const wrong = { ...f.body, originalCid: 'other-grant' };
  expect((await post(f.statusPath, wrong, f.proof())).status).toBe(401);
  const conflict = await post(f.statusPath, wrong, f.proof('lease-status', f.statusPath, wrong.originalCid));
  expect(conflict.status).toBe(409);
  expect(await conflict.json()).toEqual({ error: 'Original grant CID does not match the approved lease', code: 'request_binding' });
});

test('the request must carry a valid body and proof format', async () => {
  const f = await fixture('l'.repeat(26));
  expect((await post(f.statusPath, null, f.proof())).status).toBe(400);
  expect((await post(f.statusPath, { bodyCid: f.body.bodyCid }, f.proof())).status).toBe(400);
  expect((await post(f.statusPath, f.body, 'bad-format')).status).toBe(400);
  expect((await post(f.statusPath, f.body)).status).toBe(401);
});

test('the authenticated requester receives 429 after spending its minute budget', async () => {
  const f = await fixture('m'.repeat(26), 'pending');
  for (let attempt = 0; attempt < 60; attempt++) {
    expect((await post(f.statusPath, f.body, f.proof())).status).toBe(200);
  }
  const limited = await post(f.statusPath, f.body, f.proof());
  expect(limited.status).toBe(429);
  expect(Number(limited.headers.get('Retry-After'))).toBeGreaterThan(0);
  expect(await limited.json()).toEqual({ error: 'Too many requests', code: 'rate_limited' });
});

test('many authenticated requesters can poll without blocking a new requester', async () => {
  const now = new Date();
  setSystemTime(now);
  try {
    const existing = await fixture('p'.repeat(26), 'pending');
    const usedProof = existing.proof();
    expect((await post(existing.statusPath, existing.body, usedProof)).status).toBe(200);
    for (let requester = 0; requester < 170; requester++) {
      const prefix = String.fromCharCode(97 + Math.floor(requester / 26), 97 + requester % 26);
      const f = await fixture(prefix + 'z'.repeat(24), 'pending');
      for (let attempt = 0; attempt < 60; attempt++) {
        expect((await post(f.statusPath, f.body, f.proof())).status).toBe(200);
      }
    }
    const newcomer = await fixture('q'.repeat(26), 'pending');
    expect((await post(newcomer.statusPath, newcomer.body, newcomer.proof())).status).toBe(200);
    expect((await post(existing.statusPath, existing.body, existing.proof())).status).toBe(200);
    expect((await post(existing.statusPath, existing.body, usedProof)).status).toBe(401);
  } finally {
    setSystemTime();
  }
}, 120_000);

test('the replay limit applies only to its requester key and preserves earlier proofs', async () => {
  const start = Math.floor(Date.now() / 1000) * 1000;
  setSystemTime(new Date(start));
  try {
    const f = await fixture('r'.repeat(26), 'pending');
    const freshProof = () => f.proof('lease-status', f.statusPath, null, Math.floor(Date.now() / 1000) + 59);
    expect((await post(f.statusPath, f.body, freshProof())).status).toBe(200);
    let recentProof = '';
    for (const [offset, count] of [[0, 59], [60_000, 60], [120_000, 8]] as const) {
      setSystemTime(new Date(start + offset));
      for (let attempt = 0; attempt < count; attempt++) {
        recentProof = freshProof();
        expect((await post(f.statusPath, f.body, recentProof)).status).toBe(200);
      }
    }

    const limited = await post(f.statusPath, f.body, freshProof());
    expect(limited.status).toBe(429);
    expect(limited.headers.get('Retry-After')).toBe('59');

    const other = await fixture('s'.repeat(26), 'pending');
    expect((await post(other.statusPath, other.body, other.proof())).status).toBe(200);

    expect((await post(f.statusPath, f.body, recentProof)).status).toBe(401);

    setSystemTime(new Date(start + 180_000));
    expect((await post(f.statusPath, f.body, freshProof())).status).toBe(200);
  } finally {
    setSystemTime();
  }
});
