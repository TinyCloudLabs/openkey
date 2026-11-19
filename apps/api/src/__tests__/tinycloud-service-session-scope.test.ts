import { describe, expect, test } from 'bun:test';
import { SECRETS_SPACE } from '@tinycloud/bootstrap';
import { Wallet } from 'ethers';
import { OPENKEY_LEGACY_SPACE, createSessionNode } from '../services/tinycloud-service';

// The SIWE that OpenKey's managed key signs for the `openkey` and `secrets`
// sessions must stay limited to those spaces. node-sdk 2.11 adds the `account`
// registry space (kv, sql, delegation/list, capabilities) unless
// `includeAccountRegistryPermissions` is false.
const privateKey = '11'.repeat(32);
const address = new Wallet(`0x${privateKey}`).address;

describe('TinyCloud session sign-in scope', () => {
  test.each([
    [OPENKEY_LEGACY_SPACE, [OPENKEY_LEGACY_SPACE, SECRETS_SPACE]],
    [SECRETS_SPACE, [SECRETS_SPACE]],
  ])('%s session requests no account space', (prefix, expectedSpaces) => {
    const node = createSessionNode(privateKey, prefix) as unknown as {
      auth: {
        resolveSignInCapabilities(
          address: string,
          chainId: number,
        ): { spaceId: string; spaceAbilities: Record<string, unknown> };
      };
    };
    const plan = node.auth.resolveSignInCapabilities(address, 1);
    // Space ids end in `:<space name>`.
    const spaces = Object.keys(plan.spaceAbilities)
      .map((id) => id.slice(id.lastIndexOf(':') + 1))
      .sort();

    expect(plan.spaceId.endsWith(`:${prefix}`)).toBe(true);
    expect(spaces).toEqual([...expectedSpaces].sort());
    expect(spaces).not.toContain('account');
  });

  // TC-3115: the SDK's own account bootstrap must not run in `signIn()`: for a first sign-in it makes ~20 requests
  // one at a time (about 9 s against the production node), twice per /api/secrets/enable, and aborts anyway.
  test.each([OPENKEY_LEGACY_SPACE, SECRETS_SPACE])('%s session skips the SDK account bootstrap', async (prefix) => {
    const node = createSessionNode(privateKey, prefix) as unknown as {
      bootstrapAccountIfNeeded(): Promise<boolean>;
      _bootstrapStatus?: { skipped: boolean; reason?: string };
    };
    expect(await node.bootstrapAccountIfNeeded()).toBe(false);
    expect(node._bootstrapStatus).toEqual({ skipped: true, reason: 'auto-bootstrap-disabled' });
  });

  // Without TINYCLOUD_URL, OpenKey's own sessions reach the production node at tee.node.tinycloud.xyz.
  test.skipIf(process.env.TINYCLOUD_URL !== undefined)('sessions default to tee.node.tinycloud.xyz', () => {
    const node = createSessionNode(privateKey, SECRETS_SPACE) as unknown as { auth: { tinycloudHosts: string[] } };
    expect(node.auth.tinycloudHosts).toEqual(['https://tee.node.tinycloud.xyz']);
  });
});
