import { afterAll, beforeAll, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@openkey/db';
import { Pool } from 'pg';
import { DeviceAuthorizationService } from '../services/device-authorization';
import { createPrismaDeviceAuthorizationStore } from '../services/device-authorization-store';

// This interleaving requires two READ COMMITTED PostgreSQL connections; PGlite
// serializes the transactions. CI supplies a disposable service database.
const connectionString = process.env.DEVICE_AUTH_TEST_DATABASE_URL;
if (!connectionString) {
  test.skip('device redemption/cleanup overlap needs DEVICE_AUTH_TEST_DATABASE_URL', () => {});
} else {
  const root = resolve(import.meta.dir, '../../../..');
  const sql = new Pool({ connectionString });
  const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString }) });

  beforeAll(async () => {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const migration of migrations) {
      await sql.query(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    }
  }, 90_000);
  afterAll(async () => { await prisma.$disconnect(); await sql.end(); });

  test('sweep winning after a consume read cannot yield a successful but unrecoverable redemption', async () => {
    const deadline = Date.now() + 60_000;
    let nowMs = deadline - 1;
    const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
    const id = 'read-committed-consume-sweep';
    await prisma.deviceAuthorization.create({ data: {
      id, userCode: 'OVERLAP1', deviceSecretHash: digest('fixture-device'),
      codeChallenge: digest('fixture-verifier'), sessionDid: 'did:key:fixture',
      publicJwk: {}, relayPublicJwk: {},
      permissions: { version: 2, requested: [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }], ttlSeconds: 3600 },
      nodeOrigin: 'https://node.tinycloud.xyz', shareOrigin: 'https://share.tinycloud.xyz',
      delegationExpiresAt: new Date(deadline + 3_600_000), transactionExpiresAt: new Date(deadline),
      requestedAt: new Date(deadline - 600_000), requestIpHash: 'fixture-ip',
      nextPollAt: new Date(deadline), pollIntervalSeconds: 2, status: 'APPROVED',
      encryptedResult: JSON.stringify({ fixture: 'opaque-encrypted-relay' }),
    } });
    let release!: () => void;
    let captured!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const read = new Promise<void>((resolve) => { captured = resolve; });
    const delayedDatabase = {
      deviceAuthorization: {
        findUnique: prisma.deviceAuthorization.findUnique.bind(prisma.deviceAuthorization),
        updateManyAndReturn: async (...args: Parameters<typeof prisma.deviceAuthorization.updateManyAndReturn>) => {
          captured();
          await gate;
          return prisma.deviceAuthorization.updateManyAndReturn(...args);
        },
      },
      $transaction: <T>(run: (tx: unknown) => Promise<T>) => prisma.$transaction(async (tx) => run({
        deviceAuthorization: {
          findFirst: async (...args: Parameters<typeof tx.deviceAuthorization.findFirst>) => {
            const value = await tx.deviceAuthorization.findFirst(...args);
            captured();
            await gate;
            return value;
          },
          updateMany: tx.deviceAuthorization.updateMany.bind(tx.deviceAuthorization),
          updateManyAndReturn: async (...args: Parameters<typeof tx.deviceAuthorization.updateManyAndReturn>) => {
            captured();
            await gate;
            return tx.deviceAuthorization.updateManyAndReturn(...args);
          },
        },
      }), { timeout: 30_000 }),
    };
    const options = {
      verificationOrigin: 'https://openkey.test',
      encryptionSecret: 'isolated-device-test-secret-long-enough', now: () => new Date(nowMs),
    };
    const delayed = new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(delayedDatabase), options);
    const store = createPrismaDeviceAuthorizationStore(prisma);
    const ordinary = new DeviceAuthorizationService(store, options);
    const credentials = { transactionId: id, deviceSecret: 'fixture-device', codeVerifier: 'fixture-verifier' };
    const first = delayed.poll(credentials).then((value) => value.status, (error: { code: string }) => error.code);
    try {
      await read;
      nowMs = deadline + 1;
      expect(await store.purgeExpiredResults(new Date(nowMs))).toBe(1);
    } finally { release(); }
    expect(await first).toBe('expired_token');
    await expect(ordinary.poll(credentials)).rejects.toMatchObject({ code: 'expired_token' });
    expect(await prisma.deviceAuthorization.findUnique({ where: { id } }))
      .toMatchObject({ status: 'APPROVED', consumedAt: null, encryptedResult: null });
  }, 40_000);
}
