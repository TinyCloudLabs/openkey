// TC-2615: declining a device authorization makes the poll answer access_denied, not invalid_grant.
import { describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { DeviceAuthorizationService, MemoryDeviceAuthorizationStore, sessionDidForPublicJwk } from './device-authorization';

const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const credentials = { deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy', codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy' };

async function started() {
  let nowMs = Date.UTC(2026, 10, 9, 12, 0, 0);
  const service = new DeviceAuthorizationService(new MemoryDeviceAuthorizationStore(), {
    verificationOrigin: 'https://openkey.so',
    encryptionSecret: 'test-device-authorization-secret-is-long-enough',
    now: () => new Date(nowMs),
  });
  const publicJwk = { kty: 'OKP', crv: 'Ed25519', x: randomBytes(32).toString('base64url') };
  const transaction = await service.start({
    deviceSecretHash: digest(credentials.deviceSecret),
    codeChallenge: digest(credentials.codeVerifier),
    sessionDid: sessionDidForPublicJwk(publicJwk),
    publicJwk,
    relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }),
    permissions: [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }],
    nodeOrigin: 'https://node.tinycloud.xyz',
    shareOrigin: 'https://share.tinycloud.xyz',
  }, '203.0.113.9');
  const poll = () => service.poll({ transactionId: transaction.transactionId, ...credentials });
  return { service, transaction, poll, advance: (ms: number) => { nowMs += ms; } };
}

describe('denying a device authorization', () => {
  test('the poll answers access_denied, repeatedly', async () => {
    const { service, transaction, poll, advance } = await started();
    expect(await service.deny(transaction.transactionId)).toEqual({ status: 'denied' });
    await expect(poll()).rejects.toMatchObject({ code: 'access_denied', status: 400 });
    advance(5000);
    await expect(poll()).rejects.toMatchObject({ code: 'access_denied' });
  });

  test('the answer needs the device credentials and survives the transaction window', async () => {
    const { service, transaction, advance } = await started();
    await service.deny(transaction.transactionId);
    await expect(service.poll({ transactionId: transaction.transactionId, ...credentials, deviceSecret: 'wrong-secret' }))
      .rejects.toMatchObject({ code: 'invalid_grant', status: 401 });
    advance(24 * 60 * 60 * 1000);
    await expect(service.poll({ transactionId: transaction.transactionId, ...credentials })).rejects.toMatchObject({ code: 'access_denied' });
  });

  test('a denied code can no longer be looked up or approved', async () => {
    const { service, transaction } = await started();
    await service.deny(transaction.transactionId);
    expect(await service.lookup(transaction.userCode)).toBeNull();
    await expect(service.approve(transaction.transactionId, 'user-1', {})).rejects.toMatchObject({ code: 'expired_token', status: 410 });
  });

  test('denying twice is fine; an unknown or expired authorization is refused', async () => {
    const { service, transaction } = await started();
    await service.deny(transaction.transactionId);
    await expect(service.deny(transaction.transactionId)).resolves.toEqual({ status: 'denied' });
    await expect(service.deny('unknown-transaction')).rejects.toMatchObject({ code: 'expired_token', status: 410 });
    const second = await started();
    second.advance(24 * 60 * 60 * 1000);
    await expect(second.service.deny(second.transaction.transactionId)).rejects.toMatchObject({ code: 'expired_token' });
  });
});
