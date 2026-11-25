// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  TINYCLOUD_ONE_VERIFIED_REQUESTERS,
  VERIFIED_REQUESTERS,
  type VerifiedRequesterEntry,
  isVerifiedRequesterEntry,
  verifiedApprovalRequester,
} from './delegate-link-policy';
import type { RequesterScopePolicy } from './requester-scope-policy';

const ONE = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
const APP = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const OTHER = 'did:key:z6Mkm7pWmPt7DDUanxuPcqVpxjfQwbL4z5FYNJQc7UG85YbU';
const policy: RequesterScopePolicy = {
  maxLifetimeSeconds: 3600,
  rules: [{ kind: 'path', service: 'tinycloud.kv', spaces: ['secrets'], actions: ['tinycloud.kv/get'], pathPrefixes: ['vault/secrets/'], segmentPatterns: ['^[A-Z][A-Z0-9_]*$'] }],
};
const entry = { did: APP, displayName: 'Example App', returnTo: 'Example App', policy };
const inPolicy = { permissions: [{ service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/NAME', actions: ['tinycloud.kv/get'] }], grantLifetimeSeconds: 3600 };

describe('verifiedApprovalRequester', () => {
  test('a valid listed app key names its signer and return destination', () => {
    expect(isVerifiedRequesterEntry(entry)).toBe(true);
    expect(verifiedApprovalRequester(APP, [], [entry], inPolicy, inPolicy)).toEqual({ displayName: 'Example App', returnTo: 'Example App' });
  });

  test('only the exact listed DID receives the app name', () => {
    for (const issuer of [OTHER, '', APP.toUpperCase(), `${APP} `, APP.slice(0, -1)]) {
      expect(verifiedApprovalRequester(issuer, [], [entry], inPolicy, inPolicy)).toBeNull();
    }
  });

  test('a listed key is named only for a request inside its policy', () => {
    const out = (over: object) => verifiedApprovalRequester(APP, [], [entry], { ...inPolicy, ...over }, inPolicy);
    expect(out({})).toEqual({ displayName: 'Example App', returnTo: 'Example App' });
    expect(out({ grantLifetimeSeconds: 3601 })).toBeNull();
    expect(out({ permissions: [{ ...inPolicy.permissions[0], actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] }] })).toBeNull();
    expect(out({ permissions: [{ ...inPolicy.permissions[0], path: 'vault/other/NAME' }] })).toBeNull();
    expect(out({ renewal: { leaseLifetimeSeconds: 60 } })).toBeNull();
  });

  test('a listed key is not named before its request has loaded or its message is prepared', () => {
    expect(verifiedApprovalRequester(APP, [], [entry], null, inPolicy)).toBeNull();
    expect(verifiedApprovalRequester(APP, [], [entry], inPolicy, null)).toBeNull();
  });

  test('a listed key is not named when the signed message is outside its policy, even for an in-policy request', () => {
    const wider = { ...inPolicy, permissions: [{ ...inPolicy.permissions[0], path: 'vault/secrets/' }] };
    expect(verifiedApprovalRequester(APP, [], [entry], inPolicy, wider)).toBeNull();
  });

  test('a TinyCloud One key is named only through its policy entry', () => {
    const one = [{ did: ONE, policy }];
    expect(verifiedApprovalRequester(ONE, one, [], inPolicy, inPolicy)).toEqual({ displayName: 'TinyCloud One', returnTo: 'TinyCloud One' });
    expect(verifiedApprovalRequester(ONE, one, [], { ...inPolicy, grantLifetimeSeconds: 3601 }, inPolicy)).toBeNull();
    expect(verifiedApprovalRequester(ONE, [], [], inPolicy, inPolicy)).toBeNull();
  });

  test('invalid keys and unsafe or reserved names cannot enter the list', () => {
    for (const invalid of [
      { ...entry, did: 'did:web:example.test' },
      { ...entry, displayName: 'TinyCloud One' },
      { ...entry, displayName: 'TinyCloud CLI' },
      { ...entry, displayName: '' },
      { ...entry, displayName: 'x'.repeat(49) },
      { ...entry, displayName: 'Example\nApp' },
      { ...entry, returnTo: '' },
      { ...entry, returnTo: 'TinyCloud One' },
      { ...entry, policy: undefined },
      { ...entry, policy: { ...policy, rules: [] } },
      { ...entry, policy: { ...policy, maxLifetimeSeconds: 0 } },
    ] as VerifiedRequesterEntry[]) {
      expect(isVerifiedRequesterEntry(invalid)).toBe(false);
      expect(verifiedApprovalRequester(invalid.did, [], [invalid], inPolicy, inPolicy)).toBeNull();
    }
  });

  test('the empty built-in lists name no signer', () => {
    expect(VERIFIED_REQUESTERS).toEqual([]);
    expect(TINYCLOUD_ONE_VERIFIED_REQUESTERS).toEqual([]);
    expect(verifiedApprovalRequester(APP, TINYCLOUD_ONE_VERIFIED_REQUESTERS, VERIFIED_REQUESTERS, inPolicy, inPolicy)).toBeNull();
    expect(verifiedApprovalRequester(ONE, TINYCLOUD_ONE_VERIFIED_REQUESTERS, VERIFIED_REQUESTERS, inPolicy, inPolicy)).toBeNull();
  });
});
