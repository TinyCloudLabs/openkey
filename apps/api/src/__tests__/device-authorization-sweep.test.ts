import { afterAll, beforeAll, describe, expect, spyOn, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import {
  DEVICE_AUTH_RECOVERY_TTL_MS,
  DeviceAuthorizationService,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import * as resultSweep from '../services/device-authorization-store';

// Other API tests replace modules process-wide. Run real Prisma and tracked
// migrations in a child so their mock modules cannot capture this client.
const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_DEVICE_SWEEP_TEST_CHILD !== '1') {
  test('device result idle cleanup and deadline race against real Prisma', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: { ...process.env, OPENKEY_DEVICE_SWEEP_TEST_CHILD: '1', NODE_ENV: 'test', TEE_MODE: 'development' },
      stdout: 'pipe', stderr: 'pipe',
    });
    const [stdout, stderr, exit] = await Promise.all([
      new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
    ]);
    expect(exit, stdout + stderr).toBe(0);
  }, 120_000);
} else {
  let db: PGlite;
  let prisma: PrismaClient;
  let nowMs = Date.now();
  const now = () => new Date(nowMs);
  const permissions = [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }];
  const digest = (value: string) => createHash('sha256').update(value).digest('base64url');

  beforeAll(async () => {
    db = new PGlite();
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const migration of migrations) {
      await db.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    }
    prisma = new PrismaClient({ adapter: new PrismaPGlite(db) });
    await prisma.user.create({ data: { id: 'fixture-user', email: 'device-sweep@example.test', name: 'Sweep Fixture' } });
  }, 90_000);
  afterAll(async () => { await prisma?.$disconnect(); await db?.close(); });

  function fixture() {
    const store = resultSweep.createPrismaDeviceAuthorizationStore(prisma);
    const service = new DeviceAuthorizationService(store, {
      verificationOrigin: 'https://openkey.test',
      encryptionSecret: 'isolated-test-device-secret-long-enough', now,
    });
    return { store, service };
  }

  async function redeemed() {
    nowMs = Date.now();
    const { store, service } = fixture();
    const deviceSecret = randomBytes(32).toString('base64url');
    const codeVerifier = randomBytes(32).toString('base64url');
    const publicJwk = { kty: 'OKP', crv: 'Ed25519', x: randomBytes(32).toString('base64url') };
    const relayPublicJwk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
    const request = {
      deviceSecretHash: digest(deviceSecret), codeChallenge: digest(codeVerifier),
      sessionDid: sessionDidForPublicJwk(publicJwk), publicJwk, relayPublicJwk,
      permissions, nodeOrigin: 'https://node.tinycloud.xyz', shareOrigin: 'https://share.tinycloud.xyz',
    };
    const transaction = await service.start(request, randomBytes(12).toString('hex'));
    const relay = {
      version: 1 as const, algorithm: 'ECDH-P256-A256GCM' as const,
      ephemeralPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }),
      nonce: randomBytes(12).toString('base64url'), ciphertext: randomBytes(64).toString('base64url'),
    };
    await service.approve(transaction.transactionId, 'fixture-user', {
      relay,
      binding: {
        transactionId: transaction.transactionId, sessionDid: request.sessionDid,
        nodeOrigin: request.nodeOrigin, shareOrigin: request.shareOrigin, permissions,
        delegationExpiresAt: new Date(nowMs + 60 * 60 * 1000).toISOString(),
      },
    });
    const credentials = { transactionId: transaction.transactionId, deviceSecret, codeVerifier };
    return { service, store, credentials, transaction, relay };
  }

  describe('durable device result cleanup', () => {
    test('clears an idle redeemed result on the scheduled tick without any further request', async () => {
      let tick: (() => Promise<void>) | undefined;
      const timer = spyOn(globalThis, 'setInterval').mockImplementation(((callback: () => Promise<void>) => {
        tick = callback;
        return { unref() {} } as NodeJS.Timeout;
      }) as typeof setInterval);
      let stop: (() => void) | undefined;
      try {
        const { service, store, credentials, transaction } = await redeemed();
        nowMs = new Date((await store.findById(transaction.transactionId))!.transactionExpiresAt).getTime() - 1;
        expect((await service.poll(credentials)).status).toBe('approved');
        const runner = resultSweep.startDeviceAuthorizationResultSweep(store, now);
        stop = runner.stop;
        await runner.started;
        expect((await prisma.deviceAuthorization.findUnique({ where: { id: transaction.transactionId } }))!.encryptedResult).not.toBeNull();
        nowMs += DEVICE_AUTH_RECOVERY_TTL_MS;
        await tick!();
        expect((await prisma.deviceAuthorization.findUnique({ where: { id: transaction.transactionId } }))!.encryptedResult).toBeNull();
      } finally {
        stop?.();
        timer.mockRestore();
      }
    });

    test('catches up at startup with no new request and leaves already cleared rows unchanged', async () => {
      const { service, store, credentials, transaction } = await redeemed();
      expect((await service.poll(credentials)).status).toBe('approved');
      nowMs += DEVICE_AUTH_RECOVERY_TTL_MS;
      const runner = resultSweep.startDeviceAuthorizationResultSweep(store, now);
      try {
        await runner.started;
        const row = await prisma.deviceAuthorization.findUnique({ where: { id: transaction.transactionId } });
        expect(row!.encryptedResult).toBeNull();
        await store.purgeExpiredResults(now());
        expect((await prisma.deviceAuthorization.findUnique({ where: { id: transaction.transactionId } }))!.encryptedResult).toBeNull();
      } finally { runner.stop(); }
    });

    test('limits each database sweep to one batch and drains a larger backlog without revisiting cleared rows', async () => {
      const { store } = fixture();
      nowMs = Date.now();
      const expired = new Date(nowMs - DEVICE_AUTH_RECOVERY_TTL_MS);
      const future = new Date(nowMs + 60 * 60 * 1000);
      const count = 101;
      await prisma.deviceAuthorization.createMany({ data: Array.from({ length: count }, (_, index) => ({
        id: `expired-sweep-${index}`, userCode: `SWEEP${String(index).padStart(5, '0')}`,
        deviceSecretHash: 'hash', codeChallenge: 'challenge', sessionDid: 'did:key:test',
        publicJwk: {}, relayPublicJwk: {}, permissions: [], nodeOrigin: 'https://node.tinycloud.xyz',
        shareOrigin: 'https://share.tinycloud.xyz', delegationExpiresAt: future,
        transactionExpiresAt: expired, requestedAt: expired, requestIpHash: 'sweep-fixture',
        nextPollAt: expired, pollIntervalSeconds: 2, status: 'CONSUMED', consumedAt: expired,
        encryptedResult: 'encrypted-fixture',
      })) });
      await store.purgeExpiredResults(now());
      expect(await prisma.deviceAuthorization.count({ where: { encryptedResult: { not: null }, requestIpHash: 'sweep-fixture' } })).toBe(1);
      await store.purgeExpiredResults(now());
      expect(await prisma.deviceAuthorization.count({ where: { encryptedResult: { not: null }, requestIpHash: 'sweep-fixture' } })).toBe(0);
      await store.purgeExpiredResults(now());
      expect(await prisma.deviceAuthorization.count({ where: { encryptedResult: { not: null }, requestIpHash: 'sweep-fixture' } })).toBe(0);
    });

    test('preserves a concurrently consumed result across a stale approved snapshot and approval deadline', async () => {
      const { service, store, credentials, transaction, relay } = await redeemed();
      nowMs = new Date((await store.findById(transaction.transactionId))!.transactionExpiresAt).getTime() - 1;
      let release!: () => void;
      let captured!: () => void;
      const gate = new Promise<void>((resolve) => { release = resolve; });
      const snapshotRead = new Promise<void>((resolve) => { captured = resolve; });
      const delayedStore = { ...store, findById: async (id: string) => {
        const detached = await store.findById(id);
        captured();
        await gate;
        return detached;
      } };
      const delayed = new DeviceAuthorizationService(delayedStore, {
        verificationOrigin: 'https://openkey.test',
        encryptionSecret: 'isolated-test-device-secret-long-enough', now,
      });
      const late = delayed.poll(credentials);
      await snapshotRead;
      const first = await service.poll(credentials);
      const consumedAt = (await store.findById(transaction.transactionId))!.consumedAt;
      nowMs += 2;
      release();
      await expect(late).resolves.toEqual(first);
      expect(await service.poll(credentials)).toEqual(first);
      const row = await prisma.deviceAuthorization.findUnique({ where: { id: transaction.transactionId } });
      expect(row).toMatchObject({ status: 'CONSUMED', consumedAt });
      expect(JSON.parse(row!.encryptedResult!)).toEqual(relay);
    });
  });
}
