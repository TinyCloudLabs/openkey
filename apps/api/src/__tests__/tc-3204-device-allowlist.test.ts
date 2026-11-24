import { describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  DEVICE_AUTH_CLOCK_SKEW_MS,
  DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS,
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import { sessionAbilitiesFromPermissions, type DelegationPermissionEntry } from '../routes/delegate-session';

// /api/delegate signs a device transaction only for device-flow services and actions, the same allowlist
// device start applies.

const DECRYPT = 'tinycloud.encryption/decrypt';
const signer = { address: '0xA8763f2b67aa9C807d2277a698cb071e3D86204A', chainId: 1 };
const kv = { service: 'tinycloud.kv', space: 'default', path: 'notes/', actions: ['tinycloud.kv/get'] };
const capabilities = { service: 'tinycloud.capabilities', space: 'default', path: '', actions: ['tinycloud.capabilities/read'] };

describe('/api/delegate signing for a device transaction admits only device-flow services and actions', () => {
  const services: Array<[string, string]> = [
    ['a doubled prefix', 'tinycloud.tinycloud.encryption'],
    ['an empty segment', 'tinycloud..encryption'],
    ['a slash separator', 'tinycloud/encryption'],
    ['a URN-style name', 'urn:tinycloud:encryption'],
    ['the short kv name', 'kv'],
    ['an upper-case kv name', 'TINYCLOUD.KV'],
    ['sql', 'tinycloud.sql'],
  ];
  test.each(services)('refuses %s', (_name, service) => {
    const entry: DelegationPermissionEntry = { service, space: 'default', path: 'notes/', actions: [DECRYPT] };
    expect(() => sessionAbilitiesFromPermissions([capabilities, entry], signer, { deviceTransaction: true }))
      .toThrow('permissions[1].service is not available over device authorization');
  });

  const smuggled: Array<[string, DelegationPermissionEntry]> = [
    ['decrypt on a kv entry', { ...kv, actions: ['tinycloud.kv/get', DECRYPT] }],
    ['a capabilities action on a kv entry', { ...kv, actions: ['tinycloud.capabilities/read'] }],
    ['a kv wildcard', { ...kv, actions: ['tinycloud.kv/*'] }],
    ['delegate on a capabilities entry', { ...capabilities, actions: ['tinycloud.capabilities/read', 'tinycloud.capabilities/delegate'] }],
  ];
  test.each(smuggled)('refuses %s', (_name, entry) => {
    expect(() => sessionAbilitiesFromPermissions([entry], signer, { deviceTransaction: true }))
      .toThrow('permissions[0].actions contains an ability that is not available over device authorization');
  });

  test('signs every device-flow kv action beside capabilities/read', () => {
    const all = { ...kv, actions: ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata', 'tinycloud.kv/put', 'tinycloud.kv/del'] };
    const abilities = sessionAbilitiesFromPermissions([all, capabilities], signer, { deviceTransaction: true });
    expect(Object.values(abilities.spaceAbilities)).toEqual([{ kv: { 'notes/': all.actions }, capabilities: { '': capabilities.actions } }]);
    expect(Object.keys(abilities.rawAbilities)).toEqual([]);
  });
});

describe('outside a device transaction, a default-space decrypt entry is never promoted to the raw network', () => {
  test('{tinycloud.encryption, default, ""} signs no raw encryption resource', () => {
    const decrypt = { service: 'tinycloud.encryption', space: 'default', path: '', actions: [DECRYPT] };
    const abilities = sessionAbilitiesFromPermissions([capabilities, decrypt], signer);
    expect(Object.keys(abilities.rawAbilities)).toEqual([]);
  });
});

describe('a device request with no explicit lifetime is bounded by the standard device lifetime', () => {
  test('accepts DEFAULT_TTL + clock skew and refuses 1 ms more', async () => {
    const nowMs = Date.UTC(2026, 7, 14, 12, 0, 0);
    const service = new DeviceAuthorizationService(new MemoryDeviceAuthorizationStore(), {
      verificationOrigin: 'https://openkey.so',
      encryptionSecret: 'test-device-authorization-secret-is-long-enough',
      now: () => new Date(nowMs),
    });
    const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
    const publicJwk = { kty: 'OKP', crv: 'Ed25519', x: randomBytes(32).toString('base64url') };
    const nodeOrigin = 'https://node.tinycloud.xyz';
    const { transactionId } = await service.start({
      deviceSecretHash: digest('device-secret-with-at-least-256-bits-of-entropy'),
      codeChallenge: digest('pkce-verifier-with-at-least-256-bits-of-entropy'),
      sessionDid: sessionDidForPublicJwk(publicJwk),
      publicJwk,
      relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
      permissions: [kv, capabilities],
      nodeOrigin,
      shareOrigin: 'https://share.tinycloud.xyz',
    }, '198.51.100.22');
    const bound = (ms: number) => service.assertDelegationWindow(transactionId, {
      nodeOrigin,
      jwk: publicJwk,
      expiresAt: new Date(nowMs + ms),
    });
    await bound(DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS);
    await bound(DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS + DEVICE_AUTH_CLOCK_SKEW_MS);
    await expect(bound(DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS + DEVICE_AUTH_CLOCK_SKEW_MS + 1))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 });
  });
});
