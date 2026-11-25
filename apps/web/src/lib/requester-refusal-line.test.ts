// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { requesterRefusal, verifiedApprovalRequester, type OneVerifiedRequesterEntry, type VerifiedRequesterEntry } from './delegate-link-policy';
import { requesterRefusalLine } from './requester-refusal-line';
import {
  checkRequesterScope, leadingRefusal, requesterScopeRefusals,
  type RequesterScopePolicy, type RequesterScopeRefusal, type RequesterScopeRequest,
} from './requester-scope-policy';

// A test table: the real tables are empty. One entry reads single secrets and decrypts under `secrets/`, for an hour.
const SIGNER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const OTHER = 'did:key:z6Mkm7pWmPt7DDUanxuPcqVpxjfQwbL4z5FYNJQc7UG85YbU';
const OWNER = 'did:pkh:eip155:1:0x5B38Da6a701c568545dCfcB03FcB875f56beddC4';
const policy: RequesterScopePolicy = {
  maxLifetimeSeconds: 3600,
  rules: [
    { kind: 'path', service: 'tinycloud.kv', spaces: ['secrets'], actions: ['tinycloud.kv/get'], pathPrefixes: ['vault/secrets/'], segmentPatterns: ['^[A-Z][A-Z0-9_]*$'] },
    { kind: 'encryption-network', service: 'tinycloud.encryption', spaces: ['encryption'], actions: ['tinycloud.encryption/decrypt'], network: 'default', wholeNetwork: true, keyPrefixes: ['secrets/'], keyNamePattern: '^[a-z][a-z0-9_-]*$' },
  ],
};
const entry: VerifiedRequesterEntry = { did: SIGNER, displayName: 'Example Gateway', returnTo: 'Example Gateway', policy };
const oneEntry: OneVerifiedRequesterEntry = { did: SIGNER, policy };

const read = { service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/OPENAI_API_KEY', actions: ['tinycloud.kv/get'] };
const decrypt = { service: 'tinycloud.encryption', space: 'encryption', path: `urn:tinycloud:encryption:${OWNER}:default`, actions: ['tinycloud.encryption/decrypt'] };
const inside: RequesterScopeRequest = { permissions: [read, decrypt], grantLifetimeSeconds: 3600 };
const line = (request: RequesterScopeRequest | null, signed: RequesterScopeRequest | null = inside, issuer = SIGNER) =>
  requesterRefusalLine(issuer, [], [entry], request, signed);

// The request that trips exactly one reason each, with the approved text for it.
const CASES: [RequesterScopeRefusal, RequesterScopeRequest, string][] = [
  ['lifetime', { ...inside, grantLifetimeSeconds: 3601 }, 'This link asks for longer access than Example Gateway is allowed to ask for.'],
  ['service', { ...inside, permissions: [read, { ...decrypt, service: 'tinycloud.sql', path: 'tables' }] }, 'This link asks for a service Example Gateway is not allowed to use.'],
  ['action', { ...inside, permissions: [{ ...read, actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] }, decrypt] }, 'This link asks to do something Example Gateway is not allowed to do.'],
  ['path', { ...inside, permissions: [{ ...read, path: 'vault/secrets/lowercase' }, decrypt] }, 'This link asks for data outside what Example Gateway is allowed to reach.'],
  ['space', { ...inside, permissions: [{ ...read, space: 'default' }, decrypt] }, 'This link asks for a space Example Gateway is not allowed to ask for.'],
  ['renewal', { ...inside, renewal: { leaseLifetimeSeconds: 600 } }, 'This link asks to renew access, which Example Gateway is not allowed to ask for.'],
  ['context', { ...inside, context: { note: 'x' } }, 'Example Gateway doesn’t send this kind of request.'],
  ['malformed', { permissions: 'all', grantLifetimeSeconds: 3600 }, 'OpenKey couldn’t read this link’s request.'],
  ['no-permissions', { permissions: [], grantLifetimeSeconds: 3600 }, 'OpenKey couldn’t read this link’s request.'],
];

describe('the line under "OpenKey can’t confirm who made this link"', () => {
  test('each reason shows its own approved text with the listed requester\'s name', () => {
    for (const [reason, request, text] of CASES) {
      expect(requesterScopeRefusals(policy, request), reason).toEqual([reason]);
      expect(line(request), reason).toBe(text);
    }
  });

  test('the same text comes from a prepared message that is outside the policy', () => {
    for (const [reason, signed, text] of CASES) {
      expect(line(inside, signed), reason).toBe(text);
    }
  });

  test('with several reasons the first in the order lifetime, service, action, path, space, renewal, context, unreadable shows', () => {
    const everything: RequesterScopeRequest = {
      permissions: [{ service: 'tinycloud.sql', space: 'x', path: 'y', actions: ['tinycloud.sql/read'] }],
      grantLifetimeSeconds: 9999,
      renewal: {},
      context: {},
    };
    expect(requesterScopeRefusals(policy, everything).sort()).toEqual(['context', 'lifetime', 'renewal', 'service']);
    expect(line(everything)).toBe(CASES[0]![2]);
    const order: [string, RequesterScopeRequest][] = [
      ['service', { ...everything, grantLifetimeSeconds: 3600 }],
      ['renewal', { ...inside, renewal: {}, context: {} }],
      ['context', { ...inside, context: {} }],
    ];
    const wanted = Object.fromEntries(CASES.map(([reason, , text]) => [reason, text]));
    for (const [reason, request] of order) expect(line(request), reason).toBe(wanted[reason]!);
    // A request with an action and a path fault reports the action; a path and a space fault reports the path.
    const mixed = { ...inside, permissions: [{ ...read, actions: ['tinycloud.kv/put'] }, { ...read, path: 'vault/secrets/x' }, { ...read, space: 'default' }] };
    expect(requesterScopeRefusals(policy, mixed).sort()).toEqual(['action', 'path', 'space']);
    expect(line(mixed)).toBe(wanted.action!);
    expect(leadingRefusal(['space', 'path'])).toBe('path');
    expect(leadingRefusal(['no-permissions', 'malformed'])).toBe('malformed');
    expect(leadingRefusal(['context', 'renewal', 'space'])).toBe('space');
    expect(leadingRefusal([])).toBeNull();
  });

  test('the request and the prepared message are both read: either one being outside shows its reason', () => {
    expect(line({ ...inside, context: {} }, { ...inside, grantLifetimeSeconds: 7200 })).toBe(CASES[0]![2]);
    expect(line(null, { ...inside, grantLifetimeSeconds: 7200 })).toBe(CASES[0]![2]);
    expect(line({ ...inside, grantLifetimeSeconds: 7200 }, null)).toBe(CASES[0]![2]);
  });

  test('no line for a link inside the policy, one that is not listed, or one with nothing loaded', () => {
    expect(line(inside)).toBeNull();
    expect(line(null, null)).toBeNull();
    expect(line({ ...inside, grantLifetimeSeconds: 9999 }, inside, OTHER)).toBeNull();
    expect(requesterRefusalLine(SIGNER, [], [], { ...inside, grantLifetimeSeconds: 9999 }, inside)).toBeNull();
    // An entry that is not well formed is not listed.
    const broken: VerifiedRequesterEntry = { ...entry, policy: { ...policy, rules: [] } };
    expect(requesterRefusalLine(SIGNER, [], [broken], { ...inside, grantLifetimeSeconds: 9999 }, inside)).toBeNull();
  });

  test('a TinyCloud One key is named by its list entry, and takes precedence over the other list', () => {
    const request = { ...inside, grantLifetimeSeconds: 7200 };
    expect(requesterRefusalLine(SIGNER, [oneEntry], [], request, inside)).toBe('This link asks for longer access than TinyCloud One is allowed to ask for.');
    expect(requesterRefusalLine(SIGNER, [oneEntry], [entry], request, inside)).toContain('TinyCloud One');
    expect(requesterRefusalLine(SIGNER, [{ did: SIGNER, policy: { ...policy, rules: [] } }], [], request, inside)).toBeNull();
  });

  test('a line shows only while no requester is named, and explaining a refusal never names anyone', () => {
    for (const [reason, request] of CASES) {
      expect(verifiedApprovalRequester(SIGNER, [], [entry], request, inside), reason).toBeNull();
      expect(requesterRefusal(SIGNER, [], [entry], request, inside)?.app, reason).toBe('Example Gateway');
    }
    expect(verifiedApprovalRequester(SIGNER, [], [entry], inside, inside)).toEqual({ displayName: 'Example Gateway', returnTo: 'Example Gateway' });
    expect(requesterRefusal(SIGNER, [], [entry], inside, inside)).toBeNull();
  });
});

describe('the list of reasons keeps what the check accepts and refuses', () => {
  const variants: RequesterScopeRequest[] = [
    inside,
    ...CASES.map(([, request]) => request),
    { ...inside, grantLifetimeSeconds: 0 },
    { ...inside, grantLifetimeSeconds: 1.5 },
    { ...inside, grantLifetimeSeconds: '3600' },
    { permissions: [null, read], grantLifetimeSeconds: 3600 },
    { permissions: [{ service: 'tinycloud.kv' }], grantLifetimeSeconds: 3600 },
    { permissions: [{ ...read, actions: [] }], grantLifetimeSeconds: 3600 },
    { permissions: [{ ...read, space: undefined }, decrypt], grantLifetimeSeconds: 3600 },
    { permissions: [{ ...read, path: 'vault/secrets/A?x' }, decrypt], grantLifetimeSeconds: 3600 },
    { permissions: [read, { ...read, space: 'default' }, { ...read, service: 'tinycloud.sql' }], grantLifetimeSeconds: 99999, renewal: {}, context: {} },
    { permissions: [], grantLifetimeSeconds: 99999, renewal: {} },
  ];

  test('empty exactly when the check says ok, and the check\'s reason is the first of the list', () => {
    for (const request of variants) {
      const reasons = requesterScopeRefusals(policy, request);
      const verdict = checkRequesterScope(policy, request);
      expect(verdict.ok, JSON.stringify(request)).toBe(reasons.length === 0);
      if (!verdict.ok) expect(reasons[0], JSON.stringify(request)).toBe(verdict.reason);
      expect(new Set(reasons).size).toBe(reasons.length);
    }
    expect(requesterScopeRefusals({ ...policy, rules: [] }, inside)).toEqual(['malformed']);
  });
});
