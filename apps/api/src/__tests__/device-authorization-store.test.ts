import { describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createPrismaDeviceAuthorizationStore } from '../services/device-authorization-store';
import { DeviceAuthorizationService, sessionDidForPublicJwk } from '../services/device-authorization';

type Row = Record<string, unknown>;
type Where = Record<string, unknown>;

// Minimal stand-in for the Prisma delegate: JSON columns round-trip through
// structuredClone the way Postgres JSONB does.
function fakeDatabase() {
  const owners = new Map<string, string>();
  const rows = new Map<string, Row>();
  const matches: (row: Row, where: Where) => boolean = (row, where) => Object.entries(where).every(([field, expected]) => {
    if (field === 'OR') return Array.isArray(expected) && expected.some((condition) => matches(row, condition as Where));
    if (expected && typeof expected === 'object') {
      if ('gt' in expected) return (row[field] as Date) > (expected.gt as Date);
      if ('lte' in expected) return (row[field] as Date) <= (expected.lte as Date);
      if ('not' in expected) return (row[field] ?? null) !== expected.not;
      if ('in' in expected) return Array.isArray(expected.in) && expected.in.includes(row[field]);
    }
    return (row[field] ?? null) === expected;
  });
  const table = {
    create: async ({ data }: { data: Row }) => {
      rows.set(data.id as string, structuredClone({ approvedByUserId: null, ownerDid: null, encryptedResult: null, consumedAt: null, ...data }));
    },
    findUnique: async ({ where }: { where: Where }) => structuredClone([...rows.values()].find((row) => matches(row, where)) ?? null),
    findFirst: async ({ where }: { where: Where }) => structuredClone([...rows.values()].find((row) => matches(row, where)) ?? null),
    findMany: async ({ where, take }: { where: Where; take: number }) =>
      [...rows.values()].filter((row) => matches(row, where)).sort((a, b) => String(a.id).localeCompare(String(b.id)))
        .slice(0, take).map((row) => ({ id: row.id })),
    count: async ({ where }: { where: Where }) => [...rows.values()].filter((row) => row.requestIpHash === where.requestIpHash).length,
    updateMany: async ({ where, data }: { where: Where; data: Row }) => {
      const matched = [...rows.values()].filter((row) => matches(row, where));
      for (const row of matched) Object.assign(row, structuredClone(data));
      return { count: matched.length };
    },
  };
  const ethereumKey = {
    findFirst: async ({ where }: { where: { userId: string; address: { equals: string }; archivedAt: null } }) => {
      const address = owners.get(where.userId);
      return address?.toLowerCase() === where.address.equals.toLowerCase() ? { address } : null;
    },
  };
  return {
    rows, owners, deviceAuthorization: table, ethereumKey,
    $transaction: async <T>(run: (tx: { deviceAuthorization: typeof table; ethereumKey: typeof ethereumKey }) => Promise<T>) =>
      run({ deviceAuthorization: table, ethereumKey }),
  };
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

  test('returns the same durable relay across concurrent polls and a new store instance', async () => {
    const database = fakeDatabase();
    const options = {
      verificationOrigin: 'https://openkey.so',
      encryptionSecret: 'test-device-authorization-secret-is-long-enough',
    };
    const service = new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(database), options);
    const permissions = [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }];
    const transaction = await service.start(startRequest(permissions), '203.0.113.3');
    const row = database.rows.get(transaction.transactionId)!;
    const approval = relayFor(row, permissions);
    await service.approve(transaction.transactionId, 'user-1', approval);
    const credentials = { transactionId: transaction.transactionId, deviceSecret: 'device-secret', codeVerifier: 'code-verifier' };
    const [first, concurrent] = await Promise.all([service.poll(credentials), service.poll(credentials)]);
    expect(first).toEqual(concurrent);
    expect(first.status).toBe('approved');
    const consumedAt = row.consumedAt;
    const restarted = new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(database), options);
    expect(await restarted.poll(credentials)).toEqual(first);
    expect(row).toMatchObject({ status: 'CONSUMED', consumedAt });
    expect(JSON.parse(row.encryptedResult as string)).toEqual(approval.relay);
  });

  test('purges persisted relay on recovery expiry while preserving a stable expired token result', async () => {
    const database = fakeDatabase();
    let nowMs = Date.now();
    const options = {
      verificationOrigin: 'https://openkey.so',
      encryptionSecret: 'test-device-authorization-secret-is-long-enough',
      now: () => new Date(nowMs),
    };
    const service = new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(database), options);
    const permissions = [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }];
    const transaction = await service.start(startRequest(permissions), '203.0.113.5');
    const row = database.rows.get(transaction.transactionId)!;
    await service.approve(transaction.transactionId, 'user-1', relayFor(row, permissions));
    const credentials = { transactionId: transaction.transactionId, deviceSecret: 'device-secret', codeVerifier: 'code-verifier' };
    expect((await service.poll(credentials)).status).toBe('approved');
    nowMs += 10 * 60 * 1000;
    const restarted = new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(database), options);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await expect(restarted.poll(credentials)).rejects.toMatchObject({ code: 'expired_token', status: 410 });
    }
    expect(row.encryptedResult).toBeNull();
  });

  test('sweeps expired durable relays when another request starts', async () => {
    const database = fakeDatabase();
    let nowMs = Date.now();
    const service = new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(database), {
      verificationOrigin: 'https://openkey.so',
      encryptionSecret: 'test-device-authorization-secret-is-long-enough',
      now: () => new Date(nowMs),
    });
    const permissions = [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }];
    const consumed = await service.start(startRequest(permissions), '203.0.113.6');
    const row = database.rows.get(consumed.transactionId)!;
    await service.approve(consumed.transactionId, 'user-1', relayFor(row, permissions));
    await service.poll({ transactionId: consumed.transactionId, deviceSecret: 'device-secret', codeVerifier: 'code-verifier' });
    nowMs += 10 * 60 * 1000;
    await service.start(startRequest(permissions), '203.0.113.7');
    expect(row.encryptedResult).toBeNull();
  });

  test('persists the intended owner and denies only for a linked owner key under the pending-state guard', async () => {
    const database = fakeDatabase();
    const service = new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(database), {
      verificationOrigin: 'https://openkey.so',
      encryptionSecret: 'test-device-authorization-secret-is-long-enough',
    });
    const owner = 'did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
    const permissions = [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }];
    const transaction = await service.start({ ...startRequest(permissions), owner }, '203.0.113.4');
    const row = database.rows.get(transaction.transactionId)!;
    expect(row.ownerDid).toBe(owner);
    database.owners.set('stranger', '0x0000000000000000000000000000000000000002');
    await expect(service.deny(transaction.transactionId, 'stranger'))
      .rejects.toMatchObject({ code: 'not_found', status: 404 });
    expect(row.status).toBe('PENDING');
    database.owners.set('owner-user', '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed');
    await service.deny(transaction.transactionId, 'owner-user');
    expect(row.status).toBe('DENIED');
    await expect(service.poll({ transactionId: transaction.transactionId, deviceSecret: 'device-secret', codeVerifier: 'code-verifier' }))
      .rejects.toMatchObject({ code: 'access_denied', status: 403 });
    await expect(service.deny(transaction.transactionId, 'owner-user'))
      .rejects.toMatchObject({ code: 'not_found', status: 404 });
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
