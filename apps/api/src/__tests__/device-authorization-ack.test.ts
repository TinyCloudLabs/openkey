// TC-2376: a device-flow result is spent by the client's acknowledgement, not by
// the poll that returns it, and a result nobody acknowledges still expires.
import { beforeAll, describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { Hono } from 'hono';
import {
  DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS,
  DEVICE_AUTH_TRANSACTION_TTL_MS,
  type DeviceRelayEnvelope,
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import { createPrismaDeviceAuthorizationStore } from '../services/device-authorization-store';
import type { createDeviceAuthorizationRouter as CreateDeviceAuthorizationRouter } from '../routes/device-authorization';
import { mockModules, replaceModules } from './mock-module';

// The route loads Better Auth (through the session middleware) and opens the default
// database at import, so those are replaced first and it is imported afterwards (see mock-module.ts).
replaceModules({
  '../middleware/session': () => ({ requireSession: async (_c: unknown, next: () => Promise<void>) => next() }),
});
await mockModules({ '@openkey/db': () => ({ createPrismaClient: () => ({}) }) });
let createDeviceAuthorizationRouter: typeof CreateDeviceAuthorizationRouter;
beforeAll(async () => {
  // Static import cannot work: it would load the route before the replacements above apply.
  ({ createDeviceAuthorizationRouter } = await import('../routes/device-authorization?device-ack-test' as string));
});

const MINUTE = 60 * 1000;
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const deviceSecret = 'device-secret-with-at-least-256-bits-of-entropy';
const codeVerifier = 'pkce-verifier-with-at-least-256-bits-of-entropy';
const credentials = { deviceSecret, codeVerifier };

function fixture(makeStore: () => ConstructorParameters<typeof DeviceAuthorizationService>[0] = () => new MemoryDeviceAuthorizationStore()) {
  // Starts at today's clock, not a fixed date: the Prisma store's approve query reads the wall clock, so a fixed start
  // in the past makes the stored transaction look expired and the test fails from that day on.
  let nowMs = Date.now();
  const service = new DeviceAuthorizationService(makeStore(), {
    verificationOrigin: 'https://openkey.so',
    encryptionSecret: 'test-device-authorization-secret-is-long-enough',
    now: () => new Date(nowMs),
  });
  const publicJwk = { kty: 'OKP', crv: 'Ed25519', x: randomBytes(32).toString('base64url') };
  const request = {
    deviceSecretHash: digest(deviceSecret),
    codeChallenge: digest(codeVerifier),
    sessionDid: sessionDidForPublicJwk(publicJwk),
    publicJwk,
    relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }),
    permissions: [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }],
    nodeOrigin: 'https://node.tinycloud.xyz',
    shareOrigin: 'https://share.tinycloud.xyz',
  };
  return { service, request, advance: (ms: number) => { nowMs += ms; }, now: () => new Date(nowMs) };
}

// `approveAfter`: how long the owner takes between the request and the approval.
async function approved(input = fixture(), approveAfter = 0) {
  const transaction = await input.service.start(input.request, '203.0.113.9');
  input.advance(approveAfter);
  const relay = {
    version: 1 as const,
    algorithm: 'ECDH-P256-A256GCM' as const,
    ephemeralPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }) as DeviceRelayEnvelope['ephemeralPublicJwk'],
    nonce: randomBytes(12).toString('base64url'),
    ciphertext: randomBytes(128).toString('base64url'),
  };
  await input.service.approve(transaction.transactionId, 'user-1', {
    relay,
    binding: {
      sessionDid: input.request.sessionDid,
      nodeOrigin: input.request.nodeOrigin,
      shareOrigin: input.request.shareOrigin,
      permissions: input.request.permissions,
      transactionId: transaction.transactionId,
      delegationExpiresAt: new Date(input.now().getTime() + DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS - 1000).toISOString(),
    },
  });
  const poll = () => input.service.poll({ transactionId: transaction.transactionId, ...credentials });
  const ack = (secrets: { deviceSecret: string; codeVerifier: string } = credentials) =>
    input.service.acknowledge({ transactionId: transaction.transactionId, ...secrets });
  return { ...input, transaction, relay, poll, ack };
}

describe('device authorization results are spent by acknowledgement', () => {
  test('a lost poll response is recoverable: the next poll returns the same relay', async () => {
    const flow = await approved();
    flow.advance(2000);
    const first = await flow.poll();
    flow.advance(2000);
    const retry = await flow.poll();
    expect(first).toMatchObject({ status: 'approved', relay: flow.relay });
    expect(retry).toEqual(first);
  });

  test('an acknowledgement spends the result: later polls are refused and the ciphertext is gone', async () => {
    const store = new MemoryDeviceAuthorizationStore();
    const flow = await approved(fixture(() => store));
    flow.advance(2000);
    await flow.poll();
    await flow.ack();
    flow.advance(2000);
    await expect(flow.poll()).rejects.toMatchObject({ code: 'invalid_grant', status: 409 });
    expect(await store.findById(flow.transaction.transactionId)).not.toHaveProperty('encryptedResult');
  });

  test('a repeated acknowledgement succeeds, so a lost ACK response can be retried', async () => {
    const flow = await approved();
    await flow.ack();
    await expect(flow.ack()).resolves.toEqual({ status: 'acknowledged' });
  });

  test('only the holder of both secrets may acknowledge; a refused ACK leaves the result retrievable', async () => {
    const flow = await approved();
    await expect(flow.ack({ deviceSecret: 'wrong', codeVerifier })).rejects.toMatchObject({ code: 'invalid_grant', status: 401 });
    await expect(flow.ack({ deviceSecret, codeVerifier: 'wrong' })).rejects.toMatchObject({ code: 'invalid_grant', status: 401 });
    flow.advance(2000);
    expect(await flow.poll()).toMatchObject({ status: 'approved' });
  });

  test('a transaction with no approved result has nothing to acknowledge', async () => {
    const input = fixture();
    const transaction = await input.service.start(input.request, '203.0.113.10');
    await expect(input.service.acknowledge({ transactionId: transaction.transactionId, ...credentials }))
      .rejects.toMatchObject({ code: 'invalid_grant', status: 409 });
    // The refused ACK must not have consumed the pending transaction.
    input.advance(2000);
    expect(await input.service.poll({ transactionId: transaction.transactionId, ...credentials })).toMatchObject({ status: 'pending' });
  });

  test('an unknown transaction is refused like an expired one', async () => {
    const input = fixture();
    await expect(input.service.acknowledge({ transactionId: 'no-such-transaction', ...credentials }))
      .rejects.toMatchObject({ code: 'expired_token', status: 410 });
  });

  test('a client that never acknowledges is served for ten minutes after approval, then refused', async () => {
    const input = fixture();
    // Approved with one minute of the transaction left: retention starts at approval, not at the request.
    const flow = await approved(input, DEVICE_AUTH_TRANSACTION_TTL_MS - MINUTE);
    flow.advance(5 * MINUTE);
    expect(await flow.poll()).toMatchObject({ status: 'approved' });
    flow.advance(5 * MINUTE - 2000);
    expect(await flow.poll()).toMatchObject({ status: 'approved' });
    flow.advance(2001);
    await expect(flow.poll()).rejects.toMatchObject({ code: 'expired_token', status: 410 });
    await expect(flow.ack()).rejects.toMatchObject({ code: 'expired_token', status: 410 });
  });

  test('retention survives the stored row: the Prisma store keeps the deadline with the approved scope', async () => {
    const rows = new Map<string, Record<string, unknown>>();
    const matches = (row: Record<string, unknown>, where: Record<string, unknown>) => Object.entries(where).every(([field, expected]) => {
      if (expected && typeof expected === 'object' && 'gt' in expected) return (row[field] as Date) > (expected.gt as Date);
      return (row[field] ?? null) === expected;
    });
    const table = {
      create: async ({ data }: { data: Record<string, unknown> }) => { rows.set(data.id as string, structuredClone({ approvedByUserId: null, encryptedResult: null, consumedAt: null, ...data })); },
      findUnique: async ({ where }: { where: Record<string, unknown> }) => structuredClone([...rows.values()].find((row) => matches(row, where)) ?? null),
      findFirst: async ({ where }: { where: Record<string, unknown> }) => structuredClone([...rows.values()].find((row) => matches(row, where)) ?? null),
      count: async () => rows.size,
      updateMany: async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
        const found = [...rows.values()].filter((row) => matches(row, where));
        for (const row of found) Object.assign(row, structuredClone(data));
        return { count: found.length };
      },
    };
    const database = { deviceAuthorization: table, $transaction: async <T>(run: (tx: { deviceAuthorization: typeof table }) => Promise<T>) => run({ deviceAuthorization: table }) };
    const input = fixture(() => createPrismaDeviceAuthorizationStore(database));
    const flow = await approved(input, DEVICE_AUTH_TRANSACTION_TTL_MS - MINUTE);
    flow.advance(5 * MINUTE);
    expect(await flow.poll()).toMatchObject({ status: 'approved' });
    flow.advance(2000);
    expect(await flow.poll()).toMatchObject({ status: 'approved' });
    await flow.ack();
    flow.advance(2000);
    await expect(flow.poll()).rejects.toMatchObject({ status: 409 });
    expect([...rows.values()][0]).toMatchObject({ status: 'CONSUMED', encryptedResult: null });
  });
});

describe('POST /api/device-authorizations/:id/ack', () => {
  async function route() {
    const flow = await approved();
    const app = new Hono().route('/api/device-authorizations', createDeviceAuthorizationRouter({ service: flow.service }));
    const post = (body: unknown, id = flow.transaction.transactionId) =>
      app.request(`/api/device-authorizations/${id}/ack`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { ...flow, post };
  }

  test('acknowledges with the device credentials and needs no session', async () => {
    const flow = await route();
    const response = await flow.post(credentials);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: 'acknowledged' });
  });

  test('refuses wrong credentials with the poll error shape and leaves the result retrievable', async () => {
    const flow = await route();
    const response = await flow.post({ deviceSecret: 'wrong', codeVerifier });
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: 'invalid_grant' });
    flow.advance(2000);
    expect(await flow.poll()).toMatchObject({ status: 'approved' });
  });

  test('refuses a body that is not an object', async () => {
    const flow = await route();
    expect((await flow.post(null)).status).toBe(400);
  });
});
