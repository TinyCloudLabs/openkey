// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { TINYCLOUD_ONE_VERIFIED_REQUESTERS, VERIFIED_REQUESTERS, verifiedApprovalRequester } from './delegate-link-policy';
import type { RequesterScopeRequest } from './requester-scope-policy';

const REQUESTER = 'did:key:z6Mkm7hJCGM9CygEBbAsnY25PxmwR3Ujp5ryZUHLH2ir56tF';
const OWNER = 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111';
const encryption = `urn:tinycloud:encryption:${OWNER}:default`;

function secretRequest() {
  return {
    permissions: [
      { service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/NAME', actions: ['tinycloud.kv/get'] },
      { service: 'tinycloud.encryption', space: 'encryption', path: encryption, actions: ['tinycloud.encryption/decrypt'] },
      { service: 'tinycloud.encryption', space: 'encryption', path: `${encryption}/secrets/name`, actions: ['tinycloud.encryption/decrypt'] },
    ],
    grantLifetimeSeconds: 3600,
  };
}

function name(request: RequesterScopeRequest | null, signed: RequesterScopeRequest | null, issuer = REQUESTER) {
  return verifiedApprovalRequester(issuer, TINYCLOUD_ONE_VERIFIED_REQUESTERS, VERIFIED_REQUESTERS, request, signed);
}

describe('the built-in TinyCloud One requester', () => {
  test('the exact requester receives the One name when the loaded and signed scopes fit', () => {
    expect(name(secretRequest(), secretRequest())).toEqual({ displayName: 'TinyCloud One', returnTo: 'TinyCloud One' });
  });

  test('a different requester or an unreadable scope receives no name', () => {
    expect(name(secretRequest(), secretRequest(), `${REQUESTER.slice(0, -1)}1`)).toBeNull();
    expect(name(null, secretRequest())).toBeNull();
    expect(name(secretRequest(), null)).toBeNull();
  });

  test('a path outside the secrets policy receives no name in either scope', () => {
    const loaded = secretRequest();
    loaded.permissions[0]!.path = 'vault/other/NAME';
    expect(name(loaded, secretRequest())).toBeNull();
    const signed = secretRequest();
    signed.permissions[0]!.path = 'vault/other/NAME';
    expect(name(secretRequest(), signed)).toBeNull();
  });

  test('a write action receives no name in either scope', () => {
    const loaded = secretRequest();
    loaded.permissions[0]!.actions.push('tinycloud.kv/put');
    expect(name(loaded, secretRequest())).toBeNull();
    const signed = secretRequest();
    signed.permissions[0]!.actions.push('tinycloud.kv/put');
    expect(name(secretRequest(), signed)).toBeNull();
  });

  test('more than one hour receives no name in either scope', () => {
    expect(name({ ...secretRequest(), grantLifetimeSeconds: 3601 }, secretRequest())).toBeNull();
    expect(name(secretRequest(), { ...secretRequest(), grantLifetimeSeconds: 3601 })).toBeNull();
  });

  test('a different space, network or encryption key path receives no name', () => {
    const loaded = secretRequest();
    loaded.permissions[0]!.space = 'other';
    expect(name(loaded, secretRequest())).toBeNull();
    for (const path of [`urn:tinycloud:encryption:${OWNER}:other`, `${encryption}/shares/name`, `${encryption}/secrets/scoped`]) {
      const signed = secretRequest();
      signed.permissions[2]!.path = path;
      expect(name(secretRequest(), signed), path).toBeNull();
    }
  });

  test('renewal or context receives no name in either scope', () => {
    for (const extra of [{ renewal: { leaseLifetimeSeconds: 60 } }, { context: { purpose: 'read' } }]) {
      expect(name({ ...secretRequest(), ...extra }, secretRequest())).toBeNull();
      expect(name(secretRequest(), { ...secretRequest(), ...extra })).toBeNull();
    }
  });
});
