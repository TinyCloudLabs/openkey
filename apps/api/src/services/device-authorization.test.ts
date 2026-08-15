import { describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS,
  type DeviceRelayEnvelope,
  DeviceAuthorizationError,
  DeviceAuthorizationService,
  deviceAuthorizationDescriptorDigest,
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
  const relayKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const relayPublicJwk = relayKeys.publicKey.export({ format: 'jwk' });
  const request = {
    deviceSecretHash: digest('device-secret-with-at-least-256-bits-of-entropy'),
    codeChallenge: digest('pkce-verifier-with-at-least-256-bits-of-entropy'),
    sessionDid: sessionDidForPublicJwk(publicJwk),
    publicJwk,
    relayPublicJwk,
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

function encryptedApproval(input: ReturnType<typeof fixture>, transaction: Awaited<ReturnType<DeviceAuthorizationService['start']>>) {
  const ephemeral = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const delegationExpiresAt = new Date(input.now().getTime() + DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS - 1000).toISOString();
  return {
    relay: {
      version: 1 as const,
      algorithm: 'ECDH-P256-A256GCM' as const,
      ephemeralPublicJwk: ephemeral.publicKey.export({ format: 'jwk' }) as DeviceRelayEnvelope['ephemeralPublicJwk'],
      nonce: randomBytes(12).toString('base64url'),
      ciphertext: randomBytes(128).toString('base64url'),
    },
    binding: {
      sessionDid: input.request.sessionDid,
      nodeOrigin: input.request.nodeOrigin,
      shareOrigin: input.request.shareOrigin,
      permissions: input.request.permissions,
      descriptorDigest: deviceAuthorizationDescriptorDigest({
        permissions: input.request.permissions,
        nodeOrigin: input.request.nodeOrigin,
        shareOrigin: input.request.shareOrigin,
      }),
      transactionId: transaction.transactionId,
      delegationExpiresAt,
    },
  };
}

describe('OpenKey device authorization service', () => {
  test('delivers an end-to-end encrypted relay result exactly once without plaintext disclosure', async () => {
    const input = fixture();
    const transaction = await input.service.start(input.request, '203.0.113.9');
    expect(transaction.userCode).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect(transaction.verificationUri).toBe('https://openkey.so/device');
    const lookup = await input.service.lookup(transaction.userCode);
    expect(lookup?.sessionDid).toBe(input.request.sessionDid);
    expect(lookup?.descriptor).toEqual(expect.objectContaining({
      version: 1,
      requester: { id: 'tinycloud-cli', displayLabel: 'TinyCloud CLI' },
      templateId: 'tinycloud.share.publish.v1',
      resources: { nodeOrigin: input.request.nodeOrigin, shareOrigin: input.request.shareOrigin },
    }));

    expect(await input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    })).toEqual({ status: 'pending', interval: 2 });

    const approval = encryptedApproval(input, transaction);
    await input.service.approve(transaction.transactionId, 'user-1', approval);
    const stored = await input.store.findById(transaction.transactionId);
    expect(JSON.parse(stored?.encryptedResult ?? 'null')).toEqual(approval.relay);
    expect(JSON.stringify(stored)).not.toContain('delegationHeader');

    input.advance(2000);
    const approved = await input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    });
    expect(approved.status).toBe('approved');
    if (approved.status === 'approved') {
      expect(approved.relay).toEqual(approval.relay);
      expect(approved.binding).toMatchObject({
        transactionId: transaction.transactionId,
        sessionDid: input.request.sessionDid,
        nodeOrigin: input.request.nodeOrigin,
        shareOrigin: input.request.shareOrigin,
        descriptorDigest: lookup?.descriptorDigest,
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

    const widened = encryptedApproval(input, transaction);
    widened.binding.transactionId = 'another-transaction';
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

  test('accepts the beta.7 implicit Share template but rejects unknown templates and descriptor substitution', async () => {
    const input = fixture();
    await expect(input.service.start({ ...input.request, templateId: 'other.template.v1' }, '203.0.113.14'))
      .rejects.toMatchObject({ code: 'invalid_scope' });
    const transaction = await input.service.start({ ...input.request, templateId: 'tinycloud.share.publish.v1' }, '203.0.113.14');
    const substituted = encryptedApproval(input, transaction);
    substituted.binding.descriptorDigest = 'A'.repeat(43);
    await expect(input.service.approve(transaction.transactionId, 'user-1', substituted))
      .rejects.toMatchObject({ code: 'invalid_result' });
  });

  test('returns structured validation errors for non-object request bodies', async () => {
    const input = fixture();
    await expect(input.service.start(null as never, '203.0.113.13'))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 });
    await expect(input.service.poll(null as never))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 });
  });
});
