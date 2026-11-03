// TC-2376: an approved device result nobody acknowledges must not sit in the database after its retention.
// Until clients acknowledge, every approved row would otherwise keep its ciphertext at rest for good.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import {
  DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS,
  DEVICE_AUTH_RESULT_RETENTION_MS,
  type DeviceAuthorizationStart,
  type DeviceRelayEnvelope,
  DeviceAuthorizationService,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import { createPrismaDeviceAuthorizationStore } from '../services/device-authorization-store';

const MINUTE = 60 * 1000;
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const deviceSecret = 'device-secret-with-at-least-256-bits-of-entropy';
const codeVerifier = 'pkce-verifier-with-at-least-256-bits-of-entropy';

let database: PGlite;
let client: PrismaClient;
let nowMs = Date.UTC(2026, 10, 3, 12, 0, 0);
let ip = 0;

beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  await database.exec('CREATE TABLE "user" ("id" TEXT PRIMARY KEY)');
  await database.exec(await readFile(new URL('../../../../packages/db/prisma/migrations/20260814_0001_share_device_authorization/migration.sql', import.meta.url), 'utf8'));
  await database.exec('INSERT INTO "user" ("id") VALUES (\'user-1\')');
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
});
afterAll(async () => {
  await client.$disconnect();
  await database.close();
});
beforeEach(async () => {
  await client.deviceAuthorization.deleteMany();
  nowMs = Date.UTC(2026, 10, 3, 12, 0, 0);
});

const service = () => new DeviceAuthorizationService(createPrismaDeviceAuthorizationStore(client), {
  verificationOrigin: 'https://openkey.so',
  encryptionSecret: 'test-device-authorization-secret-is-long-enough',
  now: () => new Date(nowMs),
});

interface Flow { request: DeviceAuthorizationStart; id: string }
function startInput(): DeviceAuthorizationStart {
  const publicJwk = { kty: 'OKP', crv: 'Ed25519', x: randomBytes(32).toString('base64url') };
  return {
    deviceSecretHash: digest(deviceSecret), codeChallenge: digest(codeVerifier),
    sessionDid: sessionDidForPublicJwk(publicJwk), publicJwk,
    relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }),
    permissions: [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }],
    nodeOrigin: 'https://node.tinycloud.xyz', shareOrigin: 'https://share.tinycloud.xyz',
  };
}
const startFlow = async (): Promise<Flow> => {
  const request = startInput();
  const transaction = await service().start(request, `203.0.113.${++ip}`);
  return { request, id: transaction.transactionId };
};
async function approveFlow(flow: Flow) {
  await service().approve(flow.id, 'user-1', {
    relay: {
      version: 1 as const, algorithm: 'ECDH-P256-A256GCM' as const,
      ephemeralPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }) as DeviceRelayEnvelope['ephemeralPublicJwk'],
      nonce: randomBytes(12).toString('base64url'), ciphertext: randomBytes(128).toString('base64url'),
    },
    binding: {
      sessionDid: flow.request.sessionDid, nodeOrigin: flow.request.nodeOrigin, shareOrigin: flow.request.shareOrigin,
      permissions: flow.request.permissions, transactionId: flow.id,
      delegationExpiresAt: new Date(nowMs + DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS - 1000).toISOString(),
    },
  });
}
const ciphertext = async (id: string) => (await client.deviceAuthorization.findUniqueOrThrow({ where: { id } })).encryptedResult;

describe('an approved device result that is never acknowledged', () => {
  test('keeps its ciphertext during retention and has none once retention has passed', async () => {
    const flow = await startFlow();
    await approveFlow(flow);
    expect(await ciphertext(flow.id)).not.toBeNull();
    nowMs += DEVICE_AUTH_RESULT_RETENTION_MS - MINUTE;
    await startFlow();
    expect(await ciphertext(flow.id)).not.toBeNull();
    nowMs += MINUTE;
    await startFlow();
    expect(await ciphertext(flow.id)).toBeNull();
  });

  test('only expired rows are wiped: a later approval keeps its ciphertext, and a wiped row cannot be polled', async () => {
    const early = await startFlow();
    await approveFlow(early);
    nowMs += 6 * MINUTE;
    const late = await startFlow();
    await approveFlow(late);
    nowMs += DEVICE_AUTH_RESULT_RETENTION_MS - 6 * MINUTE;
    await startFlow();
    expect(await ciphertext(early.id)).toBeNull();
    expect(await ciphertext(late.id)).not.toBeNull();
    await expect(service().poll({ transactionId: early.id, deviceSecret, codeVerifier })).rejects.toMatchObject({ code: 'expired_token', status: 410 });
  });

  test('a pending request is left alone by the sweep', async () => {
    const pending = await startFlow();
    nowMs += 5 * MINUTE;
    await startFlow();
    expect((await client.deviceAuthorization.findUniqueOrThrow({ where: { id: pending.id } })).status).toBe('PENDING');
  });
});
