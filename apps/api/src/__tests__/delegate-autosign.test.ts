import { describe, expect, test } from 'bun:test';
import {
  bootstrapEncryptionNetworkId,
  bootstrapSpaceId,
  makePkhSpaceId,
} from '@tinycloud/bootstrap';
import {
  evaluateAutoSignPolicy,
  evaluateBootstrapHostScope,
  evaluateBootstrapSessionScope,
  type RecapEntry,
} from '../routes/delegate-autosign';

const address = '0x0000000000000000000000000000000000000001';
const chainId = 1;

function entry(
  service: string,
  space: string,
  path: string,
  actions: string[],
): RecapEntry {
  return { service, space, path, actions };
}

describe('evaluateBootstrapSessionScope', () => {
  test('accepts bootstrap session capabilities from the imported allowlist', () => {
    const spaceId = bootstrapSpaceId(address, chainId, 'default');

    const decision = evaluateBootstrapSessionScope({
      address,
      chainId,
      spaceId,
      entries: [
        entry('capabilities', spaceId, '', ['tinycloud.capabilities/read']),
        entry('kv', spaceId, '/', [
          'tinycloud.kv/get',
          'tinycloud.kv/put',
          'tinycloud.kv/del',
          'tinycloud.kv/list',
          'tinycloud.kv/metadata',
        ]),
        entry('sql', spaceId, '/', ['tinycloud.sql/read', 'tinycloud.sql/write']),
      ],
    });

    expect(decision).toEqual({ allowed: true });
  });

  test('accepts the account bootstrap raw encryption capability', () => {
    const spaceId = bootstrapSpaceId(address, chainId, 'account');

    const decision = evaluateBootstrapSessionScope({
      address,
      chainId,
      spaceId,
      entries: [
        entry('capabilities', spaceId, '', ['tinycloud.capabilities/read']),
        entry('encryption', spaceId, bootstrapEncryptionNetworkId(address, chainId), [
          'tinycloud.encryption/network.create',
        ]),
      ],
    });

    expect(decision).toEqual({ allowed: true });
  });

  test('rejects capabilities outside the bootstrap allowlist', () => {
    const spaceId = bootstrapSpaceId(address, chainId, 'default');

    const decision = evaluateBootstrapSessionScope({
      address,
      chainId,
      spaceId,
      entries: [
        entry('sql', spaceId, '/', ['tinycloud.sql/admin']),
      ],
    });

    expect(decision).toMatchObject({
      allowed: false,
      code: 'outside_bootstrap_allowlist',
    });
  });
});

describe('evaluateBootstrapHostScope', () => {
  test('accepts space/host delegations for enshrined spaces', () => {
    const spaceId = bootstrapSpaceId(address, chainId, 'public');

    const decision = evaluateBootstrapHostScope({
      address,
      chainId,
      spaceId,
      entries: [
        entry('space', spaceId, '', ['tinycloud.space/host']),
      ],
    });

    expect(decision).toEqual({ allowed: true });
  });

  test('rejects host delegations for non-enshrined spaces', () => {
    const spaceId = makePkhSpaceId(address, chainId, 'openkey');

    const decision = evaluateBootstrapHostScope({
      address,
      chainId,
      spaceId,
      entries: [
        entry('space', spaceId, '', ['tinycloud.space/host']),
      ],
    });

    expect(decision).toMatchObject({
      allowed: false,
      code: 'outside_bootstrap_allowlist',
    });
  });
});

describe('evaluateAutoSignPolicy', () => {
  test('rejects otherwise allowed bootstrap scopes when Auto-Sign is disabled', () => {
    expect(evaluateAutoSignPolicy(false, { allowed: true })).toEqual({
      allowed: false,
      code: 'auto_sign_disabled',
      reason: 'Auto-Sign is disabled for this account',
    });
  });
});
