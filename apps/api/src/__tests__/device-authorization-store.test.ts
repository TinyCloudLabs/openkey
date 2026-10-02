import { describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createPrismaDeviceAuthorizationStore } from '../services/device-authorization-store';
import { DeviceAuthorizationService, sessionDidForPublicJwk } from '../services/device-authorization';

type Row = Record<string, unknown>;
type Where = Record<string, unknown>;

// Minimal stand-in for the Prisma delegate: JSON columns round-trip through
// structuredClone the way Postgres JSONB does.
function fakeDatabase() {
  const rows = new Map<string, Row>();
  const matches = (row: Row, where: Where) => Object.entries(where).every(([field, expected]) => {
    if (expected && typeof expected === 'object' && 'gt' in expected) return (row[field] as Date) > (expected.gt as Date);
    return (row[field] ?? null) === expected;
  });
  const table = {
    create: async ({ data }: { data: Row }) => {
      rows.set(data.id as string, structuredClone({ approvedByUserId: null, encryptedResult: null, consumedAt: null, ...data }));
    },
    findUnique: async ({ where }: { where: Where }) => structuredClone([...rows.values()].find((row) => matches(row, where)) ?? null),
    findFirst: async ({ where }: { where: Where }) => structuredClone([...rows.values()].find((row) => matches(row, where)) ?? null),
    count: async ({ where }: { where: Where }) => [...rows.values()].filter((row) => row.requestIpHash === where.requestIpHash).length,
    updateMany: async ({ where, data }: { where: Where; data: Row }) => {
      const matched = [...rows.values()].filter((row) => matches(row, where));
      for (const row of matched) Object.assign(row, structuredClone(data));
      return { count: matched.length };
    },
  };
  return { rows, deviceAuthorization: table, $transaction: async <T>(run: (tx: { deviceAuthorization: typeof table }) => Promise<T>) => run({ deviceAuthorization: table }) };
}

function startRequest(permissions: unknown, reason?: string) {
  const publicJwk = { kty: 'OKP', crv: 'Ed25519', x: randomBytes(32).toString('base64url') };
  return {
    deviceSecretHash: createHash('sha256').update('device-secret').digest('base64url'),
    codeChallenge: createHash('sha256').update('code-verifier').digest('base64url'),
    sessionDid: sessionDidForPublicJwk(publicJwk),
    publicJwk,
    relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
    permissions: permissions as never,
    nodeOrigin: 'https://node.tinycloud.xyz',
    shareOrigin: 'https://share.tinycloud.xyz',
    ...(reason ? { reason } : {}),
  };
}

function relayFor(record: Row, permissions: unknown) {
  return {
    relay: {
      version: 1,
      algorithm: 'ECDH-P256-A256GCM',
      ephemeralPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }),
      nonce: randomBytes(12).toString('base64url'),
      ciphertext: randomBytes(64).toString('base64url'),
    },
    binding: {
      transactionId: record.id,
      sessionDid: record.sessionDid,
      nodeOrigin: record.nodeOrigin,
      shareOrigin: record.shareOrigin,
      permissions,
      delegationExpiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    },
  };
}

describe('Prisma device authorization store', () => {
  test('persists reason and approved subset in the permissions column and relays the approved binding', async () => {
    const database = fakeDatabase();
    const service = new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(database), {
      verificationOrigin: 'https://openkey.so',
      encryptionSecret: 'test-device-authorization-secret-is-long-enough',
    });
    const requested = [
      { service: 'tinycloud.kv', space: 'default', path: 'shares/', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
      { service: 'tinycloud.capabilities', space: 'default', path: '', actions: ['tinycloud.capabilities/read'] },
    ];
    const transaction = await service.start(startRequest(requested, 'Publish notes'), '203.0.113.1');
    expect((await service.lookup(transaction.userCode))?.reason).toBe('Publish notes');

    const row = database.rows.get(transaction.transactionId)!;
    const approved = [{ ...requested[0]!, actions: ['tinycloud.kv/get'] }, requested[1]!];
    await service.approve(transaction.transactionId, 'user-1', relayFor(row, approved));
    expect(row.permissions).toEqual({ version: 2, requested, approved, reason: 'Publish notes', ttlSeconds: 30 * 24 * 60 * 60 });

    const result = await service.poll({ transactionId: transaction.transactionId, deviceSecret: 'device-secret', codeVerifier: 'code-verifier' });
    expect(result.status === 'approved' && result.binding.permissions).toEqual(approved);
  });

  test('still consumes rows approved before TC-539 with a bare permission array', async () => {
    const database = fakeDatabase();
    const service = new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(database), {
      verificationOrigin: 'https://openkey.so',
      encryptionSecret: 'test-device-authorization-secret-is-long-enough',
    });
    const legacy = [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }];
    const transaction = await service.start(startRequest(legacy), '203.0.113.2');
    const row = database.rows.get(transaction.transactionId)!;
    const encryptedResult = JSON.stringify(relayFor(row, legacy).relay);
    // The shape a pre-TC-539 deployment wrote at approval time.
    Object.assign(row, { permissions: legacy, status: 'APPROVED', encryptedResult });

    const result = await service.poll({ transactionId: transaction.transactionId, deviceSecret: 'device-secret', codeVerifier: 'code-verifier' });
    expect(result.status === 'approved' && result.binding.permissions).toEqual(legacy);
    expect(result.status === 'approved' && JSON.stringify(result.relay)).toBe(encryptedResult);
  });

  test('derives the lifetime of pending pre-TC-539 rows from their stored deadline, capped at 30 days', async () => {
    const database = fakeDatabase();
    const store = createPrismaDeviceAuthorizationStore(database);
    const service = new DeviceAuthorizationService(store, {
      verificationOrigin: 'https://openkey.so',
      encryptionSecret: 'test-device-authorization-secret-is-long-enough',
    });
    const legacy = [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }];
    const day = 24 * 60 * 60;
    const transaction = await service.start({ ...startRequest(legacy), delegationTtlSeconds: 7 * day }, '203.0.113.3');
    const row = database.rows.get(transaction.transactionId)!;
    // Pre-TC-539 rows: bare array, deadline = transaction deadline + TTL.
    Object.assign(row, { permissions: legacy });
    expect((await store.findById(transaction.transactionId))?.delegationTtlSeconds).toBe(7 * day);
    // The old API allowed 90 days.
    Object.assign(row, { delegationExpiresAt: new Date((row.transactionExpiresAt as Date).getTime() + 90 * day * 1000) });
    expect((await store.findById(transaction.transactionId))?.delegationTtlSeconds).toBe(30 * day);
  });
});
