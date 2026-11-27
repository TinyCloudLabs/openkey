import { describe, expect, test } from 'bun:test';
import { SECRETS_SPACE } from '@tinycloud/bootstrap';
import { Wallet } from 'ethers';
import { OPENKEY_LEGACY_SPACE, createSessionNode, sessionManifest } from '../services/tinycloud-service';

const privateKey = '44'.repeat(32);
const address = new Wallet(`0x${privateKey}`).address;
const space = (name: string) => `tinycloud:pkh:eip155:1:${address}:${name}`;
const kvActions = ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del', 'tinycloud.kv/list'];

function signInPlan(prefix: string) {
  const node = createSessionNode(privateKey, prefix) as unknown as {
    auth: {
      resolveSignInCapabilities(address: string, chainId: number): {
        spaceAbilities: Record<string, unknown>;
        rawAbilities?: Record<string, string[]>;
      };
    };
  };
  return node.auth.resolveSignInCapabilities(address, 1);
}

describe('the secrets session manifest', () => {
  const network = () => `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default`;

  test('asks to create the default network and to decrypt nothing', () => {
    const manifest = sessionManifest(SECRETS_SPACE, address);
    expect(manifest.permissions).toEqual([
      { service: 'tinycloud.kv', path: 'vault/secrets/', actions: ['get', 'put', 'del', 'list'] },
      { service: 'tinycloud.encryption', path: network(), actions: ['network.create'] },
    ]);
  });

  test('signs for network.create on the default network and for no decrypt', () => {
    const plan = signInPlan(SECRETS_SPACE);
    expect(plan.rawAbilities).toEqual({ [network()]: ['tinycloud.encryption/network.create'] });
    expect(JSON.stringify(plan)).not.toContain('decrypt');
    expect(plan.spaceAbilities[space(SECRETS_SPACE)]).toMatchObject({ kv: { 'vault/secrets/': kvActions } });
  });
});

describe('the openkey session manifest', () => {
  test('is the variables kv manifest', () => {
    expect(sessionManifest(OPENKEY_LEGACY_SPACE, address)).toEqual({
      name: 'OpenKey',
      space: OPENKEY_LEGACY_SPACE,
      prefix: '',
      defaults: false,
      includePublicSpace: false,
      app_id: 'so.openkey.variables',
      permissions: [{ service: 'tinycloud.kv', path: 'variables', actions: ['get', 'put', 'del', 'list'] }],
    });
    expect(signInPlan(OPENKEY_LEGACY_SPACE).rawAbilities).toBeUndefined();
  });
});
