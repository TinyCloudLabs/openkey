import { describe, expect, test } from 'bun:test';
import { SECRETS_SPACE } from '@tinycloud/bootstrap';
import { Wallet } from 'ethers';
import { OPENKEY_LEGACY_SPACE, createSessionNode } from '../services/tinycloud-service';

// TC-3443: the SIWE OpenKey's managed key signs for these sessions names exactly the paths and actions the service
// uses, never the SDK's whole-space default.
const privateKey = '22'.repeat(32);
const address = new Wallet(`0x${privateKey}`).address;
const space = (name: string) => `tinycloud:pkh:eip155:1:${address}:${name}`;
const capabilitiesRead = { '': ['tinycloud.capabilities/read'] };

function signInPlan(prefix: string) {
  const node = createSessionNode(privateKey, prefix) as unknown as {
    auth: {
      resolveSignInCapabilities(address: string, chainId: number): {
        spaceId: string;
        spaceAbilities: Record<string, unknown>;
        rawAbilities?: Record<string, string[]>;
      };
    };
  };
  return node.auth.resolveSignInCapabilities(address, 1);
}

describe('TinyCloud session manifests', () => {
  test('the openkey session can only use kv under variables', () => {
    const plan = signInPlan(OPENKEY_LEGACY_SPACE);
    expect(plan.spaceId).toBe(space(OPENKEY_LEGACY_SPACE));
    expect(plan.spaceAbilities).toEqual({
      [space(OPENKEY_LEGACY_SPACE)]: {
        kv: { variables: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del', 'tinycloud.kv/list'] },
        capabilities: capabilitiesRead,
      },
    });
    expect(plan.rawAbilities).toBeUndefined();
  });

  test('the secrets session can only use the vault secrets and decrypt on its own network', () => {
    const plan = signInPlan(SECRETS_SPACE);
    expect(plan.spaceId).toBe(space(SECRETS_SPACE));
    expect(plan.spaceAbilities).toEqual({
      [space(SECRETS_SPACE)]: {
        kv: { 'vault/secrets/': ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del', 'tinycloud.kv/list'] },
        capabilities: capabilitiesRead,
      },
    });
    expect(plan.rawAbilities).toEqual({
      [`urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default`]: [
        'tinycloud.encryption/decrypt',
        'tinycloud.encryption/network.create',
      ],
    });
  });

  test('a session for any other space is refused', () => {
    expect(() => createSessionNode(privateKey, 'default')).toThrow('No TinyCloud session manifest for space default');
  });
});
