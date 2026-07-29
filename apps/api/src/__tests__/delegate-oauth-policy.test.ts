import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import {
  canonicalCapabilityDigest,
  canonicalCapabilityJson,
  canonicalizeCoordinationosCapabilities,
  coordinationosUserNamespace,
  evaluateCoordinationosSessionRequest,
  type CoordinationosSessionPolicyInput,
} from '../services/coordinationos-session-policy';

const address = '0x31d40B62C395B9418C4198363619B11c65cD406F';
const keyId = 'key_personal_1';
const clientId = 'coordinationos-client';
const origin = 'https://coordination.example';
const now = new Date('2026-07-28T20:00:00.000Z');

function validMessage(overrides: {
  domain?: string;
  chainId?: number;
  issuedAt?: string;
  expirationTime?: string;
  abilities?: Record<string, Record<string, string[]>>;
} = {}) {
  const spaceId = `tinycloud:pkh:eip155:1:${address}:applications`;
  return prepareSession({
    address,
    chainId: overrides.chainId ?? 1,
    domain: overrides.domain ?? 'coordination.example',
    issuedAt: overrides.issuedAt ?? now.toISOString(),
    expirationTime: overrides.expirationTime ?? new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    abilities: overrides.abilities ?? {
      kv: {
        [`coordinationos/integration/v1/${coordinationosUserNamespace(keyId)}/canary`]: [
          'tinycloud.kv/get',
          'tinycloud.kv/put',
        ],
      },
    },
  }).siwe;
}

function fixture(): CoordinationosSessionPolicyInput {
  return {
    now,
    configuredClientId: clientId,
    configuredOrigin: origin,
    principal: {
      userId: 'user_1',
      clientId,
      oauthAccessTokenId: 'token_1',
      tokenDigest: 'a'.repeat(64),
    },
    client: {
      clientId,
      disabled: false,
      mode: 'PERSONAL',
      type: 'web',
      public: false,
      tokenEndpointAuthMethod: 'client_secret_basic',
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      scopes: ['openid', 'email', 'keys', 'tinycloud:session'],
    },
    user: { id: 'user_1', emailVerified: true },
    key: {
      id: keyId,
      userId: 'user_1',
      address,
      keyType: 'MANAGED',
      keyPurpose: 'PERSONAL',
      archivedAt: null,
      sealedBlob: 'sealed',
    },
    request: {
      address,
      chainId: 1,
      message: validMessage(),
      type: 'siwe',
      purpose: 'sign-in',
      keyId,
      origin,
    },
  };
}

describe('CoordinationOS TinyCloud session policy', () => {
  test('real prepareSession ReCap canonicalizes from kv and full space URI', () => {
    const result = evaluateCoordinationosSessionRequest(fixture());
    expect(result.allowed).toBe(true);
    if (!result.allowed) throw new Error(result.code);
    expect(result.canonicalCapabilities).toEqual([{
      service: 'tinycloud.kv',
      space: `tinycloud:pkh:eip155:1:${address}:applications`,
      path: `coordinationos/integration/v1/${coordinationosUserNamespace(keyId)}/canary`,
      actions: ['tinycloud.kv/get', 'tinycloud.kv/put'],
    }]);
    expect(result.evidence.capabilityDigest).toBe(
      'cd11297f7a882b9b80f0c7618294a19c1aa78eabdaea3c76778c6b1d7eba36b1',
    );
  });

  test('canonical capability digest is stable across action and entry order', () => {
    const left = canonicalizeCoordinationosCapabilities([
      { service: 'kv', space: 'space-b', path: 'b', actions: ['put', 'get'] },
      { service: 'tinycloud.kv', space: 'space-a', path: 'a', actions: ['get', 'put'] },
    ]);
    const right = canonicalizeCoordinationosCapabilities([
      { service: 'kv', space: 'space-a', path: 'a', actions: ['put', 'get'] },
      { service: 'kv', space: 'space-b', path: 'b', actions: ['get', 'put'] },
    ]);
    expect(canonicalCapabilityJson(left)).toBe(canonicalCapabilityJson(right));
    expect(canonicalCapabilityDigest(left)).toBe(canonicalCapabilityDigest(right));
  });

  const cases: Array<[string, (input: CoordinationosSessionPolicyInput) => void, string]> = [
    ['wrong client', (input) => { input.principal.clientId = 'other'; }, 'wrong_client'],
    ['disabled client', (input) => { input.client!.disabled = true; }, 'client_disabled'],
    ['public client', (input) => { input.client!.public = true; }, 'client_misconfigured'],
    ['missing scope', (input) => {
      input.client!.scopes = ['openid', 'email', 'keys'];
    }, 'missing_scope'],
    ['missing user', (input) => { input.user = null; }, 'user_not_found'],
    ['unverified user', (input) => { input.user!.emailVerified = false; }, 'email_not_verified'],
    ['missing key', (input) => { input.key = null; }, 'key_not_found'],
    ['other user key', (input) => { input.key!.userId = 'user_2'; }, 'wrong_user'],
    ['tenant key', (input) => { input.key!.keyPurpose = 'MANAGED_ACCOUNT'; }, 'wrong_key_purpose'],
    ['external key', (input) => { input.key!.keyType = 'EXTERNAL'; }, 'external_key_denied'],
    ['archived key', (input) => { input.key!.archivedAt = now; }, 'key_archived'],
    ['unsealed key', (input) => { input.key!.sealedBlob = null; }, 'key_unavailable'],
    ['address mismatch', (input) => {
      input.request.address = '0x1111111111111111111111111111111111111111';
    }, 'key_address_mismatch'],
    ['missing origin', (input) => { input.request.origin = null; }, 'missing_origin'],
    ['wrong origin', (input) => { input.request.origin = 'https://evil.example'; }, 'wrong_origin'],
    ['wrong SIWE domain', (input) => {
      input.request.message = (input.request.message as string).replace(
        'coordination.example wants',
        'evil.example wants',
      );
    }, 'siwe_domain_mismatch'],
    ['wrong chain', (input) => { input.request.chainId = 137; }, 'wrong_chain'],
    ['SIWE chain mismatch', (input) => {
      input.request.message = validMessage({ chainId: 137 });
    }, 'chain_mismatch'],
    ['wrong type', (input) => { input.request.type = 'message'; }, 'wrong_type'],
    ['wrong purpose', (input) => { input.request.purpose = 'bootstrap-session'; }, 'wrong_purpose'],
    ['malformed SIWE', (input) => { input.request.message = 'not siwe'; }, 'invalid_siwe'],
    ['missing nonce', (input) => {
      input.request.message = (input.request.message as string).replace(/^Nonce: .*\n/m, '');
    }, 'invalid_nonce'],
    ['malformed nonce', (input) => {
      input.request.message = (input.request.message as string).replace(/^Nonce: .*$/m, 'Nonce: short');
    }, 'invalid_nonce'],
    ['future issued at', (input) => {
      input.request.message = validMessage({
        issuedAt: new Date(now.getTime() + 61_000).toISOString(),
        expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
      });
    }, 'issued_at_invalid'],
    ['expired session', (input) => {
      input.request.message = validMessage({
        issuedAt: new Date(now.getTime() - 30_000).toISOString(),
        expirationTime: new Date(now.getTime() - 1_000).toISOString(),
      });
    }, 'session_expired'],
    ['session TTL exceeded', (input) => {
      input.request.message = validMessage({
        expirationTime: new Date(now.getTime() + 3_601_000).toISOString(),
      });
    }, 'session_ttl_exceeded'],
    ['consumed token', (input) => { input.tokenConsumed = true; }, 'token_consumed'],
    ['replayed nonce', (input) => { input.nonceReplayed = true; }, 'nonce_replayed'],
  ];

  test.each(cases)('%s is denied with %s', (_name, mutate, expectedCode) => {
    const input = fixture();
    mutate(input);
    const result = evaluateCoordinationosSessionRequest(input);
    expect(result).toMatchObject({ allowed: false, code: expectedCode });
  });

  test('syntactically valid wrong SIWE URI returns siwe_uri_mismatch', () => {
    const input = fixture();
    input.request.message = (input.request.message as string).replace(
      /^URI: .*$/m,
      'URI: did:key:z6Minvalid',
    );
    const result = evaluateCoordinationosSessionRequest(input);
    expect(result).toMatchObject({ allowed: false, code: 'siwe_uri_mismatch' });
  });

  test('extra capability is denied as capability_escalation', () => {
    const input = fixture();
    input.request.message = validMessage({
      abilities: {
        kv: {
          [`coordinationos/integration/v1/${coordinationosUserNamespace(keyId)}/canary`]: [
            'tinycloud.kv/get',
            'tinycloud.kv/put',
            'tinycloud.kv/delete',
          ],
        },
      },
    });
    const result = evaluateCoordinationosSessionRequest(input);
    expect(result).toMatchObject({ allowed: false, code: 'capability_escalation' });
  });
});
