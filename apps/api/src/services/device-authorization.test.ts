import { describe, expect, test } from 'bun:test';
import { createHash, randomBytes } from 'node:crypto';
import {
  DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS,
  DeviceAuthorizationError,
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from './device-authorization';

const digest = (value: string) => createHash('sha256').update(value).digest('base64url');

function fixture() {
  let nowMs = Date.UTC(2026, 7, 14, 12, 0, 0);
  const store = new MemoryDeviceAuthorizationStore();
  const service = new DeviceAuthorizationService(store, {
    verificationOrigin: 'https://openkey.so',
    encryptionSecret: 'test-device-authorization-secret-is-long-enough',
    now: () => new Date(nowMs),
  });
  const publicJwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: randomBytes(32).toString('base64url'),
  };
  const request = {
    deviceSecretHash: digest('device-secret-with-at-least-256-bits-of-entropy'),
    codeChallenge: digest('pkce-verifier-with-at-least-256-bits-of-entropy'),
    sessionDid: sessionDidForPublicJwk(publicJwk),
    publicJwk,
    permissions: [{
      service: 'tinycloud.capabilities',
      space: 'applications',
      path: '',
      actions: ['tinycloud.capabilities/read'],
    }],
    nodeOrigin: 'https://node.tinycloud.xyz',
    shareOrigin: 'https://share.tinycloud.xyz',
  };
  const advance = (milliseconds: number) => { nowMs += milliseconds; };
  return { store, service, request, publicJwk, advance, now: () => new Date(nowMs) };
}

function approvedResult(input: ReturnType<typeof fixture>, transaction: Awaited<ReturnType<DeviceAuthorizationService['start']>>) {
  return {
    delegationHeader: { Authorization: 'Bearer plaintext-delegation-must-not-be-stored' },
    delegationCid: 'bafy-device-delegation',
    spaceId: 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:applications',
    verificationMethod: input.request.sessionDid,
    jwk: input.publicJwk,
    permissions: [{
      service: 'capabilities',
      space: 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:applications',
      path: '',
      actions: ['tinycloud.capabilities/read'],
    }],
    expiresAt: new Date(input.now().getTime() + DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS - 1000).toISOString(),
    deviceBinding: {
      sessionDid: input.request.sessionDid,
      nodeOrigin: input.request.nodeOrigin,
      shareOrigin: input.request.shareOrigin,
      permissions: input.request.permissions,
      transactionId: transaction.transactionId,
    },
  };
}

describe('OpenKey device authorization service', () => {
  test('delivers an approved Share delegation exactly once without plaintext at rest', async () => {
    const input = fixture();
    const transaction = await input.service.start(input.request, '203.0.113.9');
    expect(transaction.userCode).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect(transaction.verificationUri).toBe('https://openkey.so/device');
    expect((await input.service.lookup(transaction.userCode))?.sessionDid).toBe(input.request.sessionDid);

    expect(await input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    })).toEqual({ status: 'pending', interval: 2 });

    await input.service.approve(transaction.transactionId, 'user-1', approvedResult(input, transaction));
    const stored = await input.store.findById(transaction.transactionId);
    expect(stored?.encryptedResult).not.toContain('plaintext-delegation');
    expect(JSON.stringify(stored)).not.toContain('Bearer plaintext');

    input.advance(2000);
    const approved = await input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    });
    expect(approved.status).toBe('approved');
    if (approved.status === 'approved') {
      expect(approved.delegation.delegationCid).toBe('bafy-device-delegation');
      expect(approved.delegation).not.toHaveProperty('deviceBinding');
      expect(approved.binding).toMatchObject({
        transactionId: transaction.transactionId,
        sessionDid: input.request.sessionDid,
        nodeOrigin: input.request.nodeOrigin,
        shareOrigin: input.request.shareOrigin,
      });
    }
    expect(await input.store.findById(transaction.transactionId)).not.toHaveProperty('encryptedResult');
    input.advance(2000);
    await expect(input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    })).rejects.toMatchObject({ code: 'invalid_grant', status: 409 });
  });

  test('binds the transaction to both the device secret and PKCE verifier', async () => {
    const input = fixture();
    const transaction = await input.service.start(input.request, '203.0.113.10');
    await expect(input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'wrong-secret',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    })).rejects.toMatchObject({ code: 'invalid_grant', status: 401 });
    await expect(input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'wrong-verifier',
    })).rejects.toMatchObject({ code: 'invalid_grant', status: 401 });
  });

  test('rejects widened result bindings, expiry, fast polls, expired transactions, and excess starts', async () => {
    const input = fixture();
    const transaction = await input.service.start(input.request, '203.0.113.11');
    await input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    });
    await expect(input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    })).rejects.toMatchObject({ code: 'slow_down', status: 429 });

    const widened = approvedResult(input, transaction);
    widened.deviceBinding.transactionId = 'another-transaction';
    await expect(input.service.approve(transaction.transactionId, 'user-1', widened))
      .rejects.toMatchObject({ code: 'invalid_result' });

    input.advance(10 * 60 * 1000 + 1);
    await expect(input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    })).rejects.toMatchObject({ code: 'expired_token', status: 410 });

    const rate = fixture();
    for (let index = 0; index < 5; index += 1) {
      await rate.service.start({
        ...rate.request,
        deviceSecretHash: digest(`device-secret-${index}`),
        codeChallenge: digest(`pkce-verifier-${index}`),
      }, '198.51.100.2');
    }
    await expect(rate.service.start({
      ...rate.request,
      deviceSecretHash: digest('device-secret-six'),
      codeChallenge: digest('pkce-verifier-six'),
    }, '198.51.100.2')).rejects.toBeInstanceOf(DeviceAuthorizationError);
  });

  test('rejects a DID that is not derived from the supplied public key', async () => {
    const input = fixture();
    await expect(input.service.start({ ...input.request, sessionDid: 'did:key:z6Mismatched' }, '203.0.113.12'))
      .rejects.toMatchObject({ code: 'invalid_request' });
  });
});
