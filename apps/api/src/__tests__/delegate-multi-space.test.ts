import { describe, expect, test } from 'bun:test';
import { makeSpaceId } from '@tinycloud/node-sdk-wasm';
import {
  actionKey,
  assertBaselineSubset,
  assertRequiredActions,
  entriesToSessionAbilities,
  parsePreparedRecap,
  prepareDelegationSession,
  sessionAbilitiesFromPermissions,
  type DelegationPermissionEntry,
  type RecapEntry,
} from '../routes/delegate-session';

const address = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const signer = { address, chainId: 1 };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const spaceId = (name: string) => makeSpaceId(address, 1, name);
const prepare = (permissions: DelegationPermissionEntry[], actionKeys?: string[]) => prepareDelegationSession({
  ...signer, prefix: 'default', jwk, permissions, actionKeys, expiryMs: 3600_000,
});
const tuple = (entry: RecapEntry) => entry.actions.map(action => actionKey(entry, action));
const tuples = (entries: RecapEntry[]) => entries.flatMap(tuple).sort();
const permissions: DelegationPermissionEntry[] = [
  { service: 'tinycloud.kv', space: 'account', path: 'same/', actions: ['tinycloud.kv/get'] },
  { service: 'tinycloud.kv', space: 'applications', path: 'same/', actions: ['tinycloud.kv/put', 'tinycloud.kv/list'] },
];
const expected: RecapEntry[] = permissions.map(entry => ({ ...entry, service: 'kv', space: spaceId(entry.space!) }));

describe('TC-2490 space-qualified delegation', () => {
  test('one SIWE keeps distinct actions on identical service/path in two owner spaces', () => {
    const result = prepare(permissions);
    expect(tuples(parsePreparedRecap(result.prepared.siwe))).toEqual(tuples(expected));
    expect(result.spaceId).toBe(spaceId('applications'));
  });

  test('editing removes an action in one space without copying or overwriting the other', () => {
    const selection = [tuple(expected[0]!)[0]!, tuple(expected[1]!)[0]!];
    const result = prepare(permissions, selection);
    expect(tuples(parsePreparedRecap(result.prepared.siwe))).toEqual([...selection].sort());
    expect(result.edited).toBe(true);
  });

  test('a selection cannot transfer account read authority into applications', () => {
    const moved = actionKey({ ...expected[0]!, space: spaceId('applications') }, 'tinycloud.kv/get');
    expect(() => prepare(permissions, [moved])).toThrow('Requested permissions are not available');
  });

  test('baseline containment checks the space, not only the service and path', () => {
    const baseline = sessionAbilitiesFromPermissions(permissions, signer);
    const moved = [{ ...expected[0]!, space: spaceId('applications') }];
    expect(() => assertBaselineSubset(moved, baseline)).toThrow('subset');
    expect(() => assertBaselineSubset(expected, baseline)).not.toThrow();
  });

  test('narrowing maps retain spaces before another round of subset validation', () => {
    const baseline = entriesToSessionAbilities(expected);
    expect(() => assertBaselineSubset([{ ...expected[0]!, space: spaceId('applications') }], baseline)).toThrow('subset');
    expect(() => assertBaselineSubset(expected, baseline)).not.toThrow();
  });

  test('capabilities/read is required separately in each space that requested it', () => {
    const requested = ['account', 'applications'].map(space => ({
      service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'],
    }));
    const baseline = sessionAbilitiesFromPermissions(requested, signer);
    const entries = requested.map(entry => ({ ...entry, service: 'capabilities', space: spaceId(entry.space) }));
    expect(() => assertRequiredActions(entries.slice(0, 1), baseline)).toThrow('capabilities/read');
    expect(() => assertRequiredActions(entries, baseline)).not.toThrow();
    expect(tuples(parsePreparedRecap(prepare(requested, []).prepared.siwe))).toEqual(tuples(entries));
  });

  test('owner-qualified aliases resolve to the signer without duplicating their space', () => {
    const result = prepare([
      permissions[0]!,
      { ...permissions[0]!, space: spaceId('account').toLowerCase(), actions: ['tinycloud.kv/list'] },
    ]);
    expect(tuples(parsePreparedRecap(result.prepared.siwe))).toEqual(tuples([
      { ...expected[0]!, actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
    ]));
    expect(result.spaceId).toBe(spaceId('account'));
  });

  test.each([
    'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:account',
    `tinycloud:pkh:eip155:2:${address}:account`,
    'tinycloud:other:account',
  ])('refuses another owner, chain, or unsupported space URI: %s', space => {
    expect(() => prepare([{ ...permissions[0]!, space }])).toThrow();
  });
});
