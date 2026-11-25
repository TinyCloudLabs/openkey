// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { verifiedApprovalRequester, type OneVerifiedRequesterEntry, type VerifiedRequesterEntry } from './delegate-link-policy';
import { secretOfKvPath } from '@openkey/capability-review';
import { signedScopeOfMessage as scopeOfMessage, type RequesterScopePolicy, type RequesterScopeRequest } from './requester-scope-policy';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

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

// The listed policy, as data: read single secrets (SDK secret-name shape), decrypt on the default network and one
// lowercase key under secrets/ (never the key `scoped`), at most an hour.
const policy: RequesterScopePolicy = {
  maxLifetimeSeconds: 3600,
  rules: [
    { kind: 'path', service: 'tinycloud.kv', spaces: ['secrets'], actions: ['tinycloud.kv/get'], pathPrefixes: ['vault/secrets/'], segmentPatterns: ['^[A-Z][A-Z0-9_]*$'] },
    { kind: 'encryption-network', service: 'tinycloud.encryption', spaces: ['encryption'], actions: ['tinycloud.encryption/decrypt'], network: 'default', wholeNetwork: true, keyPrefixes: ['secrets/'], keyNamePattern: '^(?!scoped$)[a-z0-9][a-z0-9_-]*$' },
  ],
};
const entry: VerifiedRequesterEntry = { did: REQUESTER, displayName: 'Example Gateway', returnTo: 'Example Gateway', policy };
const oneEntry: OneVerifiedRequesterEntry = { did: REQUESTER, policy };
const NAMED = { displayName: 'Example Gateway', returnTo: 'Example Gateway' };

// The message the approval page prepares for the request: the same grants as a recap, issued now for an hour.
// The clock is fixed at the moment the message was prepared, so an hour-long message has 3600 seconds left.
const PREPARED_AT = Date.parse('2030-01-01T00:00:00.000Z');
const signedScopeOfMessage = (message: string, signer: Parameters<typeof scopeOfMessage>[1], now = PREPARED_AT) => scopeOfMessage(message, signer, now);
const SIGNER = { label: 'Key 0', address: OWNER_ADDRESS, chainId: 1, provenance: 'managed' as const };
const SPACE = `tinycloud:pkh:eip155:1:${OWNER_ADDRESS}`;
function preparedMessage(permissions: { service: string; space: string; path: string; actions: string[] }[], seconds = 3600, signerSpace = SPACE) {
  const att: Record<string, Record<string, unknown[]>> = {};
  for (const permission of permissions) {
    const short = permission.service.slice('tinycloud.'.length);
    const resource = short === 'encryption' ? permission.path : `${signerSpace}:${permission.space}/${short}/${permission.path}`;
    att[resource] = Object.fromEntries(permission.actions.map((action) => [action, [{}]]));
  }
  const issued = new Date(PREPARED_AT);
  return [
    'app.example.test wants you to sign in with your Ethereum account:', OWNER_ADDRESS, '', '',
    `URI: ${TARGET}#${TARGET.slice('did:key:'.length)}`, 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456',
    `Issued At: ${issued.toISOString()}`, `Expiration Time: ${new Date(issued.getTime() + seconds * 1000).toISOString()}`,
    'Resources:', `- ${makeRecapResource(att)}`,
  ].join('\n');
}
const signedOf = (request: ReturnType<typeof secretRequest>, seconds = 3600): RequesterScopeRequest | null => signedScopeOfMessage(preparedMessage(request.permissions, seconds), SIGNER);
const name = (request: ReturnType<typeof secretRequest>, signed: RequesterScopeRequest | null = signedOf(request)) => verifiedApprovalRequester(REQUESTER, [], [entry], request, signed);

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

  test('a resource of another owner is not named: the signed grant is not the signer\'s own', () => {
    const request = { ...secretRequest('OPENAI_API_KEY'), permissions: secretPermissions('OPENAI_API_KEY', 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111') };
    expect(name(request)).toBeNull();
    expect(name(request, signedOf(secretRequest('OPENAI_API_KEY')))).toEqual(NAMED);
  });

  test('a request signed by another key is not named', () => {
    expect(verifiedApprovalRequester(TARGET, [], [entry], secretRequest('OPENAI_API_KEY'), signedOf(secretRequest('OPENAI_API_KEY')))).toBeNull();
  });
});

describe('the label needs both the request and the signed message inside the policy', () => {
  const request = secretRequest('OPENAI_API_KEY');

  test('no label before a message is prepared, or when it cannot be read', () => {
    expect(name(request, null)).toBeNull();
    expect(verifiedApprovalRequester(REQUESTER, [], [entry], null, signedOf(request))).toBeNull();
    expect(signedScopeOfMessage('not a siwe message', SIGNER)).toBeNull();
    expect(signedScopeOfMessage(preparedMessage(request.permissions).replace(/Expiration Time: .*\n/, ''), SIGNER)).toBeNull();
  });

  test('a clean request with a signed path that reads back wider is not named', () => {
    for (const path of ['vault/secrets/', 'vault/secrets/?x', 'vault/secrets/%3Fx', 'vault/secrets/A#x', 'vault/secrets/scoped', 'vault/secrets//A']) {
      const widened = { ...request, permissions: [{ ...request.permissions[0]!, path }, ...request.permissions.slice(1)] };
      expect(name(request, signedOf(widened)), path).toBeNull();
    }
  });

  test('a signed encryption key or network that reads back wider is not named', () => {
    const network = `urn:tinycloud:encryption:${OWNER}:default`;
    for (const path of [`${network}/secrets/`, `${network}/secrets/scoped`, `${network}/secrets/?x`, `${network}/secrets/a#x`, `${network}?x`, `${network}:other`, `${network}/shares/a`]) {
      const widened = { ...request, permissions: [request.permissions[0]!, request.permissions[1]!, { ...request.permissions[2]!, path }] };
      expect(name(request, signedOf(widened)), path).toBeNull();
    }
  });

  test('a signed message with an extra grant, a wider action, another space or a longer lifetime is not named', () => {
    const extra = { ...request, permissions: [...request.permissions, { service: 'tinycloud.sql', space: 'secrets', path: '', actions: ['tinycloud.sql/read'] }] };
    expect(name(request, signedOf(extra))).toBeNull();
    const put = { ...request, permissions: [{ ...request.permissions[0]!, actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] }, ...request.permissions.slice(1)] };
    expect(name(request, signedOf(put))).toBeNull();
    const other = { ...request, permissions: [{ ...request.permissions[0]!, space: 'default' }, ...request.permissions.slice(1)] };
    expect(name(request, signedOf(other))).toBeNull();
    expect(name(request, signedOf(request, 3601))).toBeNull();
    expect(name(request, signedOf(request, 7200))).toBeNull();
    expect(name(request, signedOf(request, 60))).toEqual(NAMED);
  });

  test('a signed space of another owner is not named', () => {
    const foreign = preparedMessage(request.permissions, 3600, 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111');
    expect(name(request, signedScopeOfMessage(foreign, SIGNER))).toBeNull();
  });

  test('a request outside the policy is not named even when the signed message is inside it', () => {
    const signed = signedOf(request);
    for (const path of ['vault/secrets/?x', 'vault/secrets/%3Fx', 'vault/secrets/A#x', 'vault/secrets/scoped', 'vault/secrets/A?', 'vault/secrets/', 'vault/secrets//A']) {
      const bad = { ...request, permissions: [{ ...request.permissions[0]!, path }, ...request.permissions.slice(1)] };
      expect(name(bad, signed), path).toBeNull();
    }
  });
});

describe('no key is named without its policy', () => {
  const request = secretRequest('OPENAI_API_KEY');
  const signed = signedOf(request);
  const narrow: RequesterScopePolicy = { maxLifetimeSeconds: 600, rules: [policy.rules[0]!] };

  test('a TinyCloud One key with a policy is named TinyCloud One for a request inside it only', () => {
    const one = (entryPolicy: RequesterScopePolicy, req = request, sig = signed) => verifiedApprovalRequester(REQUESTER, [{ did: REQUESTER, policy: entryPolicy }], [], req, sig);
    expect(one(policy)).toEqual({ displayName: 'TinyCloud One', returnTo: 'TinyCloud One' });
    expect(one(narrow)).toBeNull();
    expect(one(policy, { ...request, grantLifetimeSeconds: 3601 })).toBeNull();
    expect(one(policy, request, signedOf(request, 3601))).toBeNull();
    expect(one(policy, request, null)).toBeNull();
    expect(one(policy, request, signedOf({ ...request, permissions: [{ ...request.permissions[0]!, path: 'vault/secrets/?x' }] }))).toBeNull();
  });

  test('a One entry without a valid key or policy names nothing', () => {
    for (const bad of [{ did: 'did:web:example.test', policy }, { did: REQUESTER, policy: { ...policy, rules: [] } }, { did: REQUESTER, policy: undefined }] as unknown as OneVerifiedRequesterEntry[]) {
      expect(verifiedApprovalRequester(bad.did, [bad], [], request, signed)).toBeNull();
    }
  });

  test('a key in both lists takes the One entry and is policy-checked by it', () => {
    expect(verifiedApprovalRequester(REQUESTER, [oneEntry], [entry], request, signed)).toEqual({ displayName: 'TinyCloud One', returnTo: 'TinyCloud One' });
    expect(verifiedApprovalRequester(REQUESTER, [{ did: REQUESTER, policy: narrow }], [entry], request, signed)).toBeNull();
  });

  test('a One key in neither policy list is not named, so the key-only list names nothing here', () => {
    expect(verifiedApprovalRequester(REQUESTER, [], [], request, signed)).toBeNull();
    expect(verifiedApprovalRequester(REQUESTER, [{ ...oneEntry, did: TARGET }], [], request, signed)).toBeNull();
  });
});

describe('the secret-name pattern follows the review package', () => {
  test('a name the pattern admits is a secret name there, and a name it refuses is not', () => {
    const pattern = new RegExp((policy.rules[0] as unknown as { segmentPatterns: string[] }).segmentPatterns[0]!);
    for (const candidate of ['A', 'API_KEY', 'K9', 'A_', 'a', 'Ab', '1A', '_A', 'A-B', 'A.B', 'SCOPED', 'scoped', 'OPENAI_API_KEY', 'ÄB', 'A B']) {
      expect(pattern.test(candidate), candidate).toBe(secretOfKvPath(`vault/secrets/${candidate}`) !== null);
    }
  });
});

describe('the signed lifetime is the time left until the message expires', () => {
  const request = secretRequest('OPENAI_API_KEY');
  const message = preparedMessage(request.permissions, 3600);
  const at = (nowOffsetMs: number) => name(request, signedScopeOfMessage(message, SIGNER, PREPARED_AT + nowOffsetMs));

  test('exactly an hour left, or less as time passes, is named', () => {
    expect(at(0)).toEqual(NAMED);
    expect(at(10_000)).toEqual(NAMED);
    expect(at(3_599_000)).toEqual(NAMED);
  });

  test('more than an hour left is not named, by a fraction of a second too', () => {
    expect(at(-500)).toBeNull();
    expect(at(-1000)).toBeNull();
    expect(at(-3_600_000)).toBeNull();
  });

  test('a message that has expired is not named', () => {
    expect(at(3_600_000)).toBeNull();
    expect(at(3_700_000)).toBeNull();
  });

  test('an old Issued At does not count: an hour left on a message issued a day ago is named', () => {
    const issuedADayAgo = message.replace(/Issued At: .*\n/, `Issued At: ${new Date(PREPARED_AT - 86_400_000).toISOString()}\n`);
    expect(name(request, signedScopeOfMessage(issuedADayAgo, SIGNER))).toEqual(NAMED);
  });

  test('an unknown signer is not named: its resources are not known to be its own', () => {
    expect(name(request, signedScopeOfMessage(message, { ...SIGNER, address: '0x1111111111111111111111111111111111111111' }))).toBeNull();
  });
});
