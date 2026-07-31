import { describe, expect, test } from 'bun:test';
import { parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import { prepareDelegationSession } from '../routes/delegate-session';

// Regression tests for the CLI explicit-permission narrowing bug.
//
// Pre-fix: when a CLI request supplied `permissions` (the explicit
// `tc auth request` path), prepareDelegationSession returned before applying
// `actionKeys`. The UI showed editable checkboxes, but the resulting SIWE
// still carried every action from the CLI request. The user's edit was
// silently ignored.
//
// Post-fix: CLI permissions become the *baseline* for the same
// actionKeys narrowing that the default consent UI already uses.

const address = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const chainId = 1;
const jwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
};
const expiryMs = 60 * 60 * 1000;

function cliPermissions() {
  return [
    {
      service: 'kv',
      space: `tinycloud:pkh:eip155:${chainId}:${address.toLowerCase()}:default`,
      path: '',
      actions: ['tinycloud.kv/put', 'tinycloud.kv/get', 'tinycloud.kv/list'],
    },
  ];
}

describe('prepareDelegationSession — CLI explicit permission narrowing', () => {
  test('CLI-supplied permissions become the editable baseline', () => {
    const result = prepareDelegationSession({
      address,
      chainId,
      prefix: 'default',
      jwk,
      permissions: cliPermissions(),
      expiryMs,
    });

    const baselineActions = result.permissions
      .flatMap((p) => p.actions.map((a) => a.ability))
      .sort();
    expect(baselineActions).toEqual([
      'tinycloud.kv/get',
      'tinycloud.kv/list',
      'tinycloud.kv/put',
    ]);
    expect(result.edited).toBe(false);
    expect(result.selectedActionKeys.length).toBe(3);
  });

  test('actionKeys narrow CLI-explicit permissions (regression for the P0 bug)', () => {
    const baseline = prepareDelegationSession({
      address,
      chainId,
      prefix: 'default',
      jwk,
      permissions: cliPermissions(),
      expiryMs,
    });

    const kvListKey = baseline.permissions[0]!.actions.find(
      (a) => a.ability === 'tinycloud.kv/list',
    )!.key;

    const narrowed = prepareDelegationSession({
      address,
      chainId,
      prefix: 'default',
      jwk,
      permissions: cliPermissions(),
      actionKeys: [kvListKey],
      expiryMs,
    });

    expect(narrowed.edited).toBe(true);
    expect(narrowed.selectedActionKeys).toEqual([kvListKey]);

    const recap = parseRecapFromSiwe(narrowed.prepared.siwe) as Array<{
      service: string;
      actions: string[];
    }>;
    const kvEntry = recap.find((e) => e.service === 'kv');
    expect(kvEntry?.actions).toEqual(['tinycloud.kv/list']);
  });

  test('actionKeys must be a subset of the CLI baseline', () => {
    const baseline = prepareDelegationSession({
      address,
      chainId,
      prefix: 'default',
      jwk,
      permissions: cliPermissions(),
      expiryMs,
    });
    const kvListKey = baseline.permissions[0]!.actions.find(
      (a) => a.ability === 'tinycloud.kv/list',
    )!.key;

    const parts = kvListKey.split('\0');
    const bogusKey = [parts[0], parts[1], parts[2], 'tinycloud.sql/read'].join('\0');

    expect(() =>
      prepareDelegationSession({
        address,
        chainId,
        prefix: 'default',
        jwk,
        permissions: cliPermissions(),
        actionKeys: [bogusKey],
        expiryMs,
      }),
    ).toThrow('Requested permissions are not available for this delegation');
  });
});
