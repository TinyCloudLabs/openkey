// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { checkRequesterScope, isRequesterScopePolicy, type RequesterScopePolicy } from './requester-scope-policy';

const OWNER = 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111';
const KV = 'tinycloud.kv';
const GET = 'tinycloud.kv/get';
const ENC = 'tinycloud.encryption';
const DECRYPT = 'tinycloud.encryption/decrypt';
const network = `urn:tinycloud:encryption:${OWNER}:default`;
const secretKey = `${network}/secrets/openai_api_key`;

// A policy for a requester that reads stored secrets and decrypts on the default network, for at most an hour.
const policy: RequesterScopePolicy = {
  maxLifetimeSeconds: 3600,
  rules: [
    { kind: 'path', service: KV, spaces: ['secrets'], actions: [GET], pathPrefixes: ['vault/secrets/'], segmentsAfterPrefix: 1 },
    { kind: 'encryption-network', service: ENC, spaces: ['encryption'], actions: [DECRYPT], network: 'default', wholeNetwork: true, keyPrefixes: ['secrets/'] },
  ],
};
const read = { service: KV, space: 'secrets', path: 'vault/secrets/OPENAI_API_KEY', actions: [GET] };
const decrypt = { service: ENC, space: 'encryption', path: secretKey, actions: [DECRYPT] };
const request = (over: Record<string, unknown> = {}) => ({ permissions: [read, decrypt], grantLifetimeSeconds: 3600, ...over });
const refusal = (over: Record<string, unknown>) => {
  const verdict = checkRequesterScope(policy, request(over));
  return verdict.ok ? null : verdict.reason;
};

describe('checkRequesterScope', () => {
  test('a request inside the policy is accepted, up to the lifetime cap', () => {
    expect(checkRequesterScope(policy, request())).toEqual({ ok: true });
    expect(checkRequesterScope(policy, request({ grantLifetimeSeconds: 60 }))).toEqual({ ok: true });
    expect(checkRequesterScope(policy, request({ permissions: [read] }))).toEqual({ ok: true });
  });

  test('decrypt covers the default network and one named key under secrets/, nothing else on it', () => {
    for (const path of [network, secretKey, `${network}/secrets/a-b_c9`]) {
      expect(checkRequesterScope(policy, request({ permissions: [{ ...decrypt, path }] }))).toEqual({ ok: true });
    }
    for (const path of [`${network}/secrets/`, `${network}/secrets`, `${network}/secrets/scoped/team/name`, `${network}/shares/name`, `${network}/secrets/Name`,
      `${network}/secrets/a.b`, `${network}/secrets/../name`, `${network}/`]) {
      expect(refusal({ permissions: [{ ...decrypt, path }] }), path).toBe('path');
    }
  });

  test('a space other than the rule names is refused', () => {
    expect(refusal({ permissions: [{ ...read, space: 'tinycloud:pkh:eip155:1:0x1:secrets' }] })).toBe('space');
    expect(refusal({ permissions: [{ ...read, space: undefined }] })).toBe('space');
    expect(refusal({ permissions: [{ ...decrypt, space: 'secrets' }] })).toBe('space');
  });

  test('a rule without spaces accepts any space', () => {
    const open: RequesterScopePolicy = { maxLifetimeSeconds: 60, rules: [{ kind: 'path', service: KV, actions: [GET], pathPrefixes: ['vault/'], segmentsAfterPrefix: 1 }] };
    expect(checkRequesterScope(open, { permissions: [{ ...read, path: 'vault/NAME', space: 'anything' }], grantLifetimeSeconds: 60 })).toEqual({ ok: true });
  });

  test('a lifetime past the cap is refused with the lifetime reason', () => {
    expect(refusal({ grantLifetimeSeconds: 3601 })).toBe('lifetime');
    expect(refusal({ grantLifetimeSeconds: 86_400 })).toBe('lifetime');
  });

  test('another service, another action or another path is refused with its own reason', () => {
    expect(refusal({ permissions: [read, { service: 'tinycloud.sql', space: 's', path: '', actions: ['tinycloud.sql/read'] }] })).toBe('service');
    expect(refusal({ permissions: [{ ...read, actions: ['tinycloud.kv/put'] }] })).toBe('action');
    expect(refusal({ permissions: [{ ...read, actions: [GET, 'tinycloud.kv/del'] }] })).toBe('action');
    expect(refusal({ permissions: [{ ...decrypt, actions: ['tinycloud.encryption/key.create'] }] })).toBe('action');
    expect(refusal({ permissions: [{ ...read, path: 'vault/other/NAME' }] })).toBe('path');
    expect(refusal({ permissions: [{ ...decrypt, path: secretKey.replace(':default/', ':other/') }] })).toBe('path');
  });

  test('a path outside the prefix by trick of shape is refused', () => {
    for (const path of ['vault/secrets/', 'vault/secrets', 'vault/secretsX/NAME', '/vault/secrets/NAME', 'vault/secrets/../other', 'vault/secrets/./NAME',
      'vault/secrets//NAME', 'vault/secrets/a\\b', 'vault/secrets/a\nb', 'Vault/secrets/NAME', 'vault/other/../secrets/NAME',
      'vault/secrets/scoped/team/NAME', 'vault/secrets/a/b']) {
      expect(refusal({ permissions: [{ ...read, path }] }), path).toBe('path');
    }
  });

  test('an unreadable encryption resource is refused', () => {
    for (const path of ['', 'default', `urn:tinycloud:encryption:${OWNER}`, `urn:tinycloud:encryption:${OWNER}:default/Bad Key`]) {
      expect(refusal({ permissions: [{ ...decrypt, path }] }), path).toBe('path');
    }
  });

  test('one out-of-policy permission refuses the whole request', () => {
    expect(refusal({ permissions: [read, decrypt, { ...read, path: 'vault/other/NAME' }] })).toBe('path');
  });

  test('a request with no permissions, a renewal or a context is refused', () => {
    expect(refusal({ permissions: [] })).toBe('no-permissions');
    expect(refusal({ renewal: { leaseLifetimeSeconds: 86_400 } })).toBe('renewal');
    expect(refusal({ context: { kind: 'share-invitation' } })).toBe('context');
  });

  test('values of the wrong type are refused as malformed', () => {
    for (const over of [
      { permissions: 'x' }, { permissions: [null] }, { permissions: ['x'] },
      { permissions: [{ ...read, actions: [] }] }, { permissions: [{ ...read, actions: [GET, 1] }] },
      { permissions: [{ ...read, path: 5 }] }, { permissions: [{ ...read, service: undefined }] },
      { grantLifetimeSeconds: '3600' }, { grantLifetimeSeconds: 0 }, { grantLifetimeSeconds: -1 }, { grantLifetimeSeconds: 1.5 },
      { grantLifetimeSeconds: Number.NaN }, { grantLifetimeSeconds: undefined },
    ]) {
      expect(refusal(over), JSON.stringify(over)).toBe('malformed');
    }
  });
});

describe('isRequesterScopePolicy', () => {
  test('the example policy is well formed', () => {
    expect(isRequesterScopePolicy(policy)).toBe(true);
  });

  test('an unbounded, empty or imprecise policy is refused, and a request is never checked against it', () => {
    const rule = policy.rules[0]! as Extract<RequesterScopePolicy['rules'][number], { kind: 'path' }>;
    const enc = policy.rules[1]! as Extract<RequesterScopePolicy['rules'][number], { kind: 'encryption-network' }>;
    for (const bad of [
      { ...policy, maxLifetimeSeconds: 0 },
      { ...policy, maxLifetimeSeconds: Number.POSITIVE_INFINITY },
      { ...policy, maxLifetimeSeconds: 1.5 },
      { ...policy, rules: [] },
      { ...policy, rules: [{ ...rule, actions: [] }] },
      { ...policy, rules: [{ ...rule, service: '' }] },
      { ...policy, rules: [{ ...rule, pathPrefixes: [] }] },
      { ...policy, rules: [{ ...rule, pathPrefixes: ['/'] }] },
      { ...policy, rules: [{ ...rule, pathPrefixes: ['vault/secrets'] }] },
      { ...policy, rules: [{ ...rule, pathPrefixes: ['vault/../'] }] },
      { ...policy, rules: [{ ...rule, segmentsAfterPrefix: 0 }] },
      { ...policy, rules: [{ ...rule, spaces: [] }] },
      { ...policy, rules: [{ ...enc, network: '' }] },
      { ...policy, rules: [{ ...enc, network: 'Default' }] },
      { ...policy, rules: [{ ...enc, wholeNetwork: false, keyPrefixes: [] }] },
      { ...policy, rules: [{ ...enc, keyPrefixes: ['secrets'] }] },
      { ...policy, rules: [{ kind: 'anything', service: KV, actions: [GET] }] },
    ] as RequesterScopePolicy[]) {
      expect(isRequesterScopePolicy(bad), JSON.stringify(bad)).toBe(false);
      expect(checkRequesterScope(bad, request())).toEqual({ ok: false, reason: 'malformed' });
    }
  });
});
