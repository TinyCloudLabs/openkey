// TC-2274: a device request signs its own maximum lifetime (`delegationTtlSeconds`, no 30-day cap) and may
// add a suggested default (`suggestedTtlSeconds`, 60 s up to the maximum).
import { describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  DeviceAuthorizationError,
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import { decodeScope, encodeScope } from '../services/device-authorization-store';

const DAY = 86_400;
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');

function fixture() {
  let nowMs = Date.UTC(2026, 9, 31, 12, 0, 0);
  const store = new MemoryDeviceAuthorizationStore();
  const service = new DeviceAuthorizationService(store, {
    verificationOrigin: 'https://openkey.so',
    encryptionSecret: 'test-device-authorization-secret-is-long-enough',
    now: () => new Date(nowMs),
  });
  const publicJwk = { kty: 'OKP', crv: 'Ed25519', x: randomBytes(32).toString('base64url') };
  const relayKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const request = {
    deviceSecretHash: digest('device-secret-with-at-least-256-bits-of-entropy'),
    codeChallenge: digest('pkce-verifier-with-at-least-256-bits-of-entropy'),
    sessionDid: sessionDidForPublicJwk(publicJwk),
    publicJwk,
    relayPublicJwk: relayKeys.publicKey.export({ format: 'jwk' }),
    permissions: [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }],
    nodeOrigin: 'https://node.tinycloud.xyz',
    shareOrigin: 'https://share.tinycloud.xyz',
  };
  return { store, service, request, now: () => new Date(nowMs) };
}

async function refusal(promise: Promise<unknown>) {
  const error = await promise.then(() => null, (cause: unknown) => cause);
  expect(error).toBeInstanceOf(DeviceAuthorizationError);
  return error as DeviceAuthorizationError;
}

describe('the requested maximum lifetime', () => {
  test('a year is accepted, and so is any longer positive time a date can hold', async () => {
    const { service, request, store } = fixture();
    for (const seconds of [365 * DAY, 10 * 365 * DAY]) {
      const started = await service.start({ ...request, delegationTtlSeconds: seconds }, '203.0.113.9');
      expect((await store.findById(started.transactionId))?.delegationTtlSeconds).toBe(seconds);
    }
  });

  test.each([0, 59, -5, 1.5, '1y', null, Number.MAX_SAFE_INTEGER, 1e12])('%p is refused', async (value) => {
    const { service, request } = fixture();
    const error = await refusal(service.start({ ...request, delegationTtlSeconds: value as never }, '203.0.113.9'));
    expect(error.status).toBe(400);
  });

  test('absent still means 30 days', async () => {
    const { service, request, store } = fixture();
    const started = await service.start(request, '203.0.113.9');
    expect((await store.findById(started.transactionId))?.delegationTtlSeconds).toBe(30 * DAY);
  });

  test('approval is still bounded by the signed maximum, not by 30 days', async () => {
    const { service, request, now } = fixture();
    const started = await service.start({ ...request, delegationTtlSeconds: 365 * DAY }, '203.0.113.9');
    const window = (days: number) => service.assertDelegationWindow(started.transactionId, {
      nodeOrigin: request.nodeOrigin, jwk: request.publicJwk, expiresAt: new Date(now().getTime() + days * DAY * 1000),
    });
    await expect(window(200)).resolves.toBeUndefined();
    await expect(window(365)).resolves.toBeUndefined();
    await refusal(window(366));
  });
});

describe('the suggested default lifetime', () => {
  test('is kept and shown at lookup when it is between a minute and the maximum', async () => {
    const { service, request, store } = fixture();
    const started = await service.start({ ...request, delegationTtlSeconds: 365 * DAY, suggestedTtlSeconds: 7 * DAY }, '203.0.113.9');
    expect((await store.findById(started.transactionId))?.suggestedTtlSeconds).toBe(7 * DAY);
    expect((await service.lookup(started.userCode))?.suggestedTtlSeconds).toBe(7 * DAY);
    const same = await service.start({ ...request, delegationTtlSeconds: 3600, suggestedTtlSeconds: 3600 }, '203.0.113.9');
    expect((await service.lookup(same.userCode))?.suggestedTtlSeconds).toBe(3600);
    const minimum = await service.start({ ...request, delegationTtlSeconds: 3600, suggestedTtlSeconds: 60 }, '203.0.113.9');
    expect((await service.lookup(minimum.userCode))?.suggestedTtlSeconds).toBe(60);
  });

  test('absent means the maximum: nothing is stored or shown', async () => {
    const { service, request, store } = fixture();
    const started = await service.start({ ...request, delegationTtlSeconds: 365 * DAY }, '203.0.113.9');
    expect((await store.findById(started.transactionId))?.suggestedTtlSeconds).toBeUndefined();
    expect((await service.lookup(started.userCode))?.suggestedTtlSeconds).toBeUndefined();
  });

  test.each([59, 0, -1, 1.5, '7d', null, 365 * DAY + 1])('%p is refused', async (value) => {
    const { service, request } = fixture();
    const error = await refusal(service.start({ ...request, delegationTtlSeconds: 365 * DAY, suggestedTtlSeconds: value as never }, '203.0.113.9'));
    expect(error.status).toBe(400);
  });

  test('a suggestion above the default maximum is refused when no maximum is given', async () => {
    const { service, request } = fixture();
    await refusal(service.start({ ...request, suggestedTtlSeconds: 31 * DAY }, '203.0.113.9'));
  });
});

describe('the stored scope', () => {
  test('round-trips the maximum and the suggestion; old rows have none', () => {
    const permissions = [{ service: 'tinycloud.kv', space: 'default', path: '', actions: ['tinycloud.kv/get'] }];
    const stored = encodeScope({ permissions, delegationTtlSeconds: 365 * DAY, suggestedTtlSeconds: 7 * DAY });
    const row = { permissions: stored, delegationExpiresAt: new Date(0), transactionExpiresAt: new Date(0) };
    expect(decodeScope(row)).toMatchObject({ delegationTtlSeconds: 365 * DAY, suggestedTtlSeconds: 7 * DAY });
    const without = decodeScope({ ...row, permissions: encodeScope({ permissions, delegationTtlSeconds: 3600 }) });
    expect(without.suggestedTtlSeconds).toBeUndefined();
  });
});

describe('the one-minute minimum, from both sides', () => {
  test('60 s is accepted and 59 s is refused, for the maximum and for the suggestion', async () => {
    const { service, request, store } = fixture();
    const started = await service.start({ ...request, delegationTtlSeconds: 60 }, '203.0.113.9');
    expect((await store.findById(started.transactionId))?.delegationTtlSeconds).toBe(60);
    await refusal(service.start({ ...request, delegationTtlSeconds: 59 }, '203.0.113.9'));
    await refusal(service.start({ ...request, delegationTtlSeconds: 3600, suggestedTtlSeconds: 59 }, '203.0.113.9'));
  });
});
