// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { verifiedApprovalRequester, type VerifiedRequesterEntry } from './delegate-link-policy';

// The request a secrets gateway signs for one named secret: one KV read, decryption with the owner's default
// network, and decryption with the secret's own key (left out for the name SCOPED, which has no key of its own).
// The permissions are built the way the gateway builds them. Keys and owner address are test-only.
const REQUESTER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const TARGET = 'did:key:z6Mkm7pWmPt7DDUanxuPcqVpxjfQwbL4z5FYNJQc7UG85YbU';
const OWNER_ADDRESS = '0x5B38Da6a701c568545dCfcB03FcB875f56beddC4';
const OWNER = `did:pkh:eip155:1:${OWNER_ADDRESS}`;

function secretPermissions(name: string, owner = OWNER) {
  const permissions = [
    { service: 'tinycloud.kv', space: 'secrets', path: `vault/secrets/${name}`, actions: ['tinycloud.kv/get'] },
    { service: 'tinycloud.encryption', space: 'encryption', path: `urn:tinycloud:encryption:${owner}:default`, actions: ['tinycloud.encryption/decrypt'] },
  ];
  if (name !== 'SCOPED') {
    permissions.push({ service: 'tinycloud.encryption', space: 'encryption', path: `urn:tinycloud:encryption:${owner}:default/secrets/${name.toLowerCase()}`, actions: ['tinycloud.encryption/decrypt'] });
  }
  return permissions;
}

function secretRequest(name: string) {
  return {
    issuer: REQUESTER,
    requesterDid: REQUESTER,
    requestVersion: 1,
    targetDid: TARGET,
    targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
    nodeOrigin: 'https://node.example.test',
    permissions: secretPermissions(name),
    reason: `Use ${name} with api.example.test. To call the service for you.`,
    grantLifetimeSeconds: 3600,
    suggestedLifetimeSeconds: 3600,
    resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: 'B'.repeat(43), y: 'C'.repeat(43) },
  };
}

// The listed policy, as data: read single secrets, decrypt on the default network, at most an hour.
const entry: VerifiedRequesterEntry = {
  did: REQUESTER,
  displayName: 'Example Gateway',
  returnTo: 'Example Gateway',
  policy: {
    maxLifetimeSeconds: 3600,
    rules: [
      { kind: 'path', service: 'tinycloud.kv', spaces: ['secrets'], actions: ['tinycloud.kv/get'], pathPrefixes: ['vault/secrets/'], segmentsAfterPrefix: 1 },
      { kind: 'encryption-network', service: 'tinycloud.encryption', spaces: ['encryption'], actions: ['tinycloud.encryption/decrypt'], network: 'default', wholeNetwork: true, keyPrefixes: ['secrets/'] },
    ],
  },
};
const NAMED = { displayName: 'Example Gateway', returnTo: 'Example Gateway' };
const name = (request: ReturnType<typeof secretRequest>) => verifiedApprovalRequester(REQUESTER, [], [entry], request);

describe('a secret request from a listed gateway', () => {
  test('a request for a named secret is named, with its three permissions', () => {
    const request = secretRequest('OPENAI_API_KEY');
    expect(request.permissions).toHaveLength(3);
    expect(name(request)).toEqual(NAMED);
  });

  test('a request for SCOPED is named, with its two permissions', () => {
    const request = secretRequest('SCOPED');
    expect(request.permissions).toHaveLength(2);
    expect(name(request)).toEqual(NAMED);
  });

  test('names with digits and underscores are named', () => {
    for (const secret of ['A', 'API_KEY_2', 'K9']) expect(name(secretRequest(secret))).toEqual(NAMED);
  });

  test('a write on the secret is not named', () => {
    const request = secretRequest('OPENAI_API_KEY');
    request.permissions[0] = { ...request.permissions[0]!, actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] };
    expect(name(request)).toBeNull();
  });

  test('a different space is not named', () => {
    const kv = secretRequest('OPENAI_API_KEY');
    kv.permissions[0] = { ...kv.permissions[0]!, space: 'tinycloud:pkh:eip155:1:0x1:secrets' };
    expect(name(kv)).toBeNull();
    const enc = secretRequest('OPENAI_API_KEY');
    enc.permissions[1] = { ...enc.permissions[1]!, space: 'secrets' };
    expect(name(enc)).toBeNull();
  });

  test('a read outside vault/secrets/, or of a nested path, is not named', () => {
    for (const path of ['vault/other/NAME', 'vault/secrets/scoped/team/NAME', 'vault/secrets/../NAME', 'vault/secrets/']) {
      const request = secretRequest('OPENAI_API_KEY');
      request.permissions[0] = { ...request.permissions[0]!, path };
      expect(name(request), path).toBeNull();
    }
  });

  test('decryption elsewhere on the network, or on another network, is not named', () => {
    for (const path of [
      `urn:tinycloud:encryption:${OWNER}:default/secrets/`,
      `urn:tinycloud:encryption:${OWNER}:default/shares/name`,
      `urn:tinycloud:encryption:${OWNER}:default/secrets/scoped/team/name`,
      `urn:tinycloud:encryption:${OWNER}:default/secrets/NAME`,
      `urn:tinycloud:encryption:${OWNER}:other`,
      `urn:tinycloud:encryption:${OWNER}:other/secrets/name`,
    ]) {
      const request = secretRequest('OPENAI_API_KEY');
      request.permissions[2] = { ...request.permissions[2]!, path };
      expect(name(request), path).toBeNull();
    }
  });

  test('a lifetime of 3601 seconds is not named, 3600 is', () => {
    expect(name({ ...secretRequest('OPENAI_API_KEY'), grantLifetimeSeconds: 3601 })).toBeNull();
    expect(name({ ...secretRequest('OPENAI_API_KEY'), grantLifetimeSeconds: 3600 })).toEqual(NAMED);
  });

  test('the owner inside the encryption resource is not compared with anyone: another owner is still inside the policy', () => {
    const request = { ...secretRequest('OPENAI_API_KEY'), permissions: secretPermissions('OPENAI_API_KEY', 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111') };
    expect(name(request)).toEqual(NAMED);
  });

  test('a request signed by another key is not named', () => {
    expect(verifiedApprovalRequester(TARGET, [], [entry], secretRequest('OPENAI_API_KEY'))).toBeNull();
  });
});
