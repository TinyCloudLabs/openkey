// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { checkRequesterScope, isRequesterScopePolicy, pathFits, signedScopeRequest, type RequesterScopePolicy } from './requester-scope-policy';

const OWNER = 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111';
const KV = 'tinycloud.kv';
const GET = 'tinycloud.kv/get';
const ENC = 'tinycloud.encryption';
const DECRYPT = 'tinycloud.encryption/decrypt';
const network = `urn:tinycloud:encryption:${OWNER}:default`;
// The patterns One's secrets use: the SDK's secret-name rule, and a lowercase key name that is not `scoped`.
const SECRET_NAME = '^[A-Z][A-Z0-9_]*$';
const KEY_NAME = '^(?!scoped$)[a-z0-9][a-z0-9_-]*$';
const secretKey = `${network}/secrets/openai_api_key`;

// A policy for a requester that reads stored secrets and decrypts on the default network, for at most an hour.
const policy: RequesterScopePolicy = {
  maxLifetimeSeconds: 3600,
  rules: [
    { kind: 'path', service: KV, spaces: ['secrets'], actions: [GET], pathPrefixes: ['vault/secrets/'], segmentPatterns: [SECRET_NAME] },
    { kind: 'encryption-network', service: ENC, spaces: ['encryption'], actions: [DECRYPT], network: 'default', wholeNetwork: true, keyPrefixes: ['secrets/'], keyNamePattern: KEY_NAME },
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
    const open: RequesterScopePolicy = { maxLifetimeSeconds: 60, rules: [{ kind: 'path', service: KV, actions: [GET], pathPrefixes: ['vault/'], segmentPatterns: [SECRET_NAME] }] };
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
      { ...policy, rules: [{ ...rule, segmentPatterns: [] }] },
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

describe('a segment is an allowed-character list, not a deny list', () => {
  const kv = (path: string) => refusal({ permissions: [{ ...read, path }] });
  const key = (path: string) => refusal({ permissions: [{ ...decrypt, path }] });

  test('a query, fragment, escape or empty segment in a secret path is refused, which the node would read as a wider path', () => {
    for (const path of ['vault/secrets/?x', 'vault/secrets/%3Fx', 'vault/secrets/%3fx', 'vault/secrets/A#x', 'vault/secrets/#x', 'vault/secrets/A?', 'vault/secrets/A?x=1',
      'vault/secrets/A%2F', 'vault/secrets/A%00', 'vault/secrets/', 'vault/secrets//A', 'vault/secrets/A/', 'vault/secrets/A ', 'vault/secrets/A\tB', 'vault/secrets/A.B',
      'vault/secrets/A;x', 'vault/secrets/A:x', 'vault/secrets/\u00c4', 'vault/secrets/A\u2028', 'vault/secrets/A\u0000']) {
      expect(kv(path), JSON.stringify(path)).toBe('path');
    }
  });

  test('a name that is not the SDK secret-name shape is refused: lowercase, which includes scoped, a leading digit or underscore', () => {
    for (const name of ['scoped', 'scoped_', 'a', 'Name', 'nAME', '1A', '_A', 'A-B']) {
      expect(kv(`vault/secrets/${name}`), name).toBe('path');
    }
    for (const name of ['A', 'SCOPED', 'OPENAI_API_KEY', 'K9', 'A_', 'A__B']) {
      expect(kv(`vault/secrets/${name}`), name).toBeNull();
    }
  });

  test('the same classes on an encryption key name are refused, and so is the key that is the scoped prefix', () => {
    for (const name of ['?x', '%3Fx', 'a#x', 'a?', 'a%2fb', '', 'a/', 'a//b', 'a b', 'a.b', 'a;b', 'scoped', 'Scoped', 'A']) {
      expect(key(`${network}/secrets/${name}`), JSON.stringify(name)).toBe('path');
    }
    for (const name of ['scopedx', 'a', 'a-b_c', 'xscoped']) {
      expect(key(`${network}/secrets/${name}`), name).toBeNull();
    }
  });

  test('the same classes on the network are refused', () => {
    for (const path of [`${network}?x`, `${network}#x`, `${network}%3Fx`, `${network}/`, `${network}//`, `${network.replace(':default', ':default?x')}/secrets/a`,
      `${network.replace(':default', ':default#x')}/secrets/a`, `${network.replace(':default', ':default%3Fx')}`, `${network} `, `${network}\n`]) {
      expect(key(path), JSON.stringify(path)).toBe('path');
    }
  });

  test('a pattern that admits a query, fragment, escape, separator, dot, space, control or an empty segment is not a valid pattern', () => {
    const rule = policy.rules[0]! as Extract<RequesterScopePolicy['rules'][number], { kind: 'path' }>;
    const enc = policy.rules[1]! as Extract<RequesterScopePolicy['rules'][number], { kind: 'encryption-network' }>;
    for (const bad of ['^.*$', '^.+$', '^[^/]+$', '^\\S+$', '^\\w*$', '^[A-Z]*$', '^[A-Z?]+$', '^[A-Z#]+$', '^[A-Z%]+$', '^[A-Z/]+$', '^[A-Z\\\\]+$', '^[A-Z.]+$', '^[A-Z ]+$',
      '^[A-Z\\s]+$', '^[A-Z\\u0000-\\u001f]+$', '^[A-Z\\u2028]+$', '^[A-Z]+', '[A-Z]+$', '^[A-Z]+\\$', '^(', '', 'A']) {
      expect(isRequesterScopePolicy({ ...policy, rules: [{ ...rule, segmentPatterns: [bad] }] }), bad).toBe(false);
      expect(isRequesterScopePolicy({ ...policy, rules: [{ ...enc, keyNamePattern: bad }] }), bad).toBe(false);
    }
    expect(isRequesterScopePolicy({ ...policy, rules: [{ ...rule, segmentPatterns: [SECRET_NAME, '^[a-z]+$'], pathPrefixes: ['a/'] }] })).toBe(true);
    expect(isRequesterScopePolicy({ ...policy, rules: [{ ...rule, segmentPatterns: undefined }] } as unknown as RequesterScopePolicy)).toBe(false);
    expect(isRequesterScopePolicy({ ...policy, rules: [{ ...enc, keyNamePattern: undefined }] } as unknown as RequesterScopePolicy)).toBe(false);
  });

  test('prefixes with a dot, query, escape or odd character are not valid', () => {
    const rule = policy.rules[0]! as Extract<RequesterScopePolicy['rules'][number], { kind: 'path' }>;
    const enc = policy.rules[1]! as Extract<RequesterScopePolicy['rules'][number], { kind: 'encryption-network' }>;
    for (const prefix of ['vault/?/', 'vault/%2e/', 'vault/a.b/', 'vault/#/', 'vault//', 'va ult/', 'vault/a\\b/', 'vault/\u00e4/']) {
      expect(isRequesterScopePolicy({ ...policy, rules: [{ ...rule, pathPrefixes: [prefix] }] }), prefix).toBe(false);
      expect(isRequesterScopePolicy({ ...policy, rules: [{ ...enc, keyPrefixes: [prefix] }] }), prefix).toBe(false);
    }
  });
});

describe('signedScopeRequest', () => {
  const space = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:secrets';
  const grants = [
    { service: KV, space, path: 'vault/secrets/OPENAI_API_KEY', ownedBySelf: true, actions: [{ ability: GET }] },
    { service: ENC, space: secretKey, path: '', ownedBySelf: true, actions: [{ ability: DECRYPT }] },
  ];

  test('maps the signed grants to the request shape, so the same policy checks them', () => {
    const signed = signedScopeRequest(grants, 3600)!;
    expect(signed.permissions).toEqual([read, decrypt]);
    expect(checkRequesterScope(policy, signed)).toEqual({ ok: true });
  });

  test('a lifetime past the cap, or an unknown one, is not named', () => {
    expect(checkRequesterScope(policy, signedScopeRequest(grants, 3601)!)).toEqual({ ok: false, reason: 'lifetime' });
    expect(signedScopeRequest(grants, null)).toBeNull();
  });

  test('a grant is named only when it is known to be the signer\'s own and its service agrees with its resource', () => {
    expect(signedScopeRequest([{ ...grants[0]!, ownedBySelf: true }], 3600)).not.toBeNull();
    expect(signedScopeRequest([{ ...grants[0]!, ownedBySelf: false }], 3600)).toBeNull();
    expect(signedScopeRequest([{ ...grants[0]!, ownedBySelf: null }], 3600)).toBeNull();
    expect(signedScopeRequest([grants[0]!, { ...grants[1]!, ownedBySelf: null }], 3600)).toBeNull();
    expect(signedScopeRequest([{ ...grants[0]!, serviceMismatch: true }], 3600)).toBeNull();
    expect(signedScopeRequest([{ ...grants[0]!, serviceMismatch: false }], 3600)).not.toBeNull();
  });

  test('a signed path that reads back wider than the request is refused', () => {
    // The node reads `vault/secrets/?x` back as the prefix `vault/secrets/`.
    for (const path of ['vault/secrets/', 'vault/secrets/?x', 'vault/secrets/scoped', 'vault/secrets']) {
      expect(checkRequesterScope(policy, signedScopeRequest([{ ...grants[0]!, path }], 60)!), path).toEqual({ ok: false, reason: 'path' });
    }
  });

  test('another space or an extra grant in the signed message is refused', () => {
    expect(checkRequesterScope(policy, signedScopeRequest([{ ...grants[0]!, space: space.replace(':secrets', ':default') }], 60)!)).toEqual({ ok: false, reason: 'space' });
    expect(checkRequesterScope(policy, signedScopeRequest([...grants, { service: 'tinycloud.sql', space, path: '', ownedBySelf: true, actions: [{ ability: 'tinycloud.sql/read' }] }], 60)!)).toEqual({ ok: false, reason: 'service' });
    expect(checkRequesterScope(policy, signedScopeRequest([{ ...grants[0]!, actions: [{ ability: GET }, { ability: 'tinycloud.kv/put' }] }], 60)!)).toEqual({ ok: false, reason: 'action' });
  });
});

describe('a segment pattern is a bounded literal-and-class form', () => {
  const rule = policy.rules[0]! as Extract<RequesterScopePolicy['rules'][number], { kind: 'path' }>;
  const enc = policy.rules[1]! as Extract<RequesterScopePolicy['rules'][number], { kind: 'encryption-network' }>;
  const valid = (source: string) => isRequesterScopePolicy({ ...policy, rules: [{ ...rule, segmentPatterns: [source] }] });

  test('loose, unanchored or grouped patterns are not valid, whatever strings they happen to pass', () => {
    for (const bad of ['^.{4,}$', '^\\W{4,}$', '^B.*$', '^[A-Z]{2}.*$', '[A-Z]{2}$', '^[A-Z]{2}', '^(?:A|B)$', '^(A)$', '^[A-Z]{2}(x)$', '^A|B$', '^[^a]+$',
      '^[A-Z]{2}\\d$', '^[A-Z\\d]+$', '^A?$', '^(?=A)[A-Z]+$', '^(?!a.)[A-Z]+$', '^[A-Z]+$|^x$', '^[A-Z]{2}$\n', '^[A-Z]{9999}$', '^[]$']) {
      expect(valid(bad), bad).toBe(false);
      expect(isRequesterScopePolicy({ ...policy, rules: [{ ...enc, keyNamePattern: bad }] }), bad).toBe(false);
    }
  });

  test('bounded forms are valid, including both patterns One uses', () => {
    for (const good of ['^[A-Z][A-Z0-9_]*$', '^(?!scoped$)[a-z0-9][a-z0-9_-]*$', '^[A-Z]{2}$', '^[A-Z]{2,8}$', '^[A-Z]{2,}$', '^[a-z0-9_-]+$', '^A[0-9]*$', '^abc$']) {
      expect(valid(good), good).toBe(true);
    }
  });

  // The whole-path check is the last stop for a rule whose pattern the validator would refuse. These rules are
  // built by hand, past the validator, to show that the check alone refuses a query, fragment, escape or separator.
  test('the whole-path check alone refuses a path with a query, fragment, escape or separator', () => {
    const loose = (source: string) => ({ ...rule, segmentPatterns: [source] });
    for (const source of ['^.{4,}$', '^[A-Z]{2}.*$', '[A-Z]{2}$', '^\\W{4,}$']) {
      for (const path of ['vault/secrets/AB?x', 'vault/secrets/AB#x', 'vault/secrets/AB%3Fx', 'vault/secrets/?AB', 'vault/secrets/AB/', 'vault/secrets/A.B', 'vault/secrets/AB\\x', 'vault/secrets/AB x']) {
        expect(pathFits(loose(source), path), `${source} ${path}`).toBe(false);
      }
    }
    expect(pathFits(loose('^.{4,}$'), 'vault/secrets/ABCD')).toBe(true);
    expect(pathFits(loose('[A-Z]{2}$'), 'vault/secrets/xAB')).toBe(true);
  });
});
