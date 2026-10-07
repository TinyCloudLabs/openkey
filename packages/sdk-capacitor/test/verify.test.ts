import { expect, test } from 'bun:test';
import { tinycloud, initialized } from '@tinycloud/web-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { verifyTinyCloudDelegation } from '../src/verify';
import type { TinyCloudDelegation } from '@openkey/core';

// This creates actual Cacao bytes with the WASM used by web-sdk 2.11.
test('real WASM-signed delegations reproduce padded headers and CIDs', async () => {
  await initialized;
  let padded = 0;
  for (let i = 0; i < 12; i++) {
    const account = privateKeyToAccount(`0x${(i + 1).toString(16).padStart(64, '0')}`);
    const address = account.address;
    const prepared = tinycloud.prepareSession({
      abilities: { kv: { [`app/threads/${'x'.repeat(i)}`]: ['tinycloud.kv/get'] } },
      address, chainId: 1, domain: 'openkey.so',
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
      spaceId: `tinycloud:pkh:eip155:1:${address}:applications`,
    });
    const signature = await account.signMessage({ message: prepared.siwe });
    const signed = tinycloud.completeSessionSetup({ ...prepared, signature });
    const delegation = {
      siwe: prepared.siwe, signature,
      delegationHeader: signed.delegationHeader,
      delegationCid: signed.delegationCid,
    } as TinyCloudDelegation;
    if (signed.delegationHeader.Authorization.includes('=')) padded++;
    const bindings = {
      ensureInitialized: async () => { await initialized; },
      siweToDelegationHeaders: ({ siwe, signature }: { siwe: string; signature: string }) => tinycloud.siweToDelegationHeaders({ siwe, signature }),
      computeCid: (bytes: Uint8Array, codec: bigint) => tinycloud.computeCid(bytes, codec),
    };
    await verifyTinyCloudDelegation(delegation, bindings);
    await expect(verifyTinyCloudDelegation({ ...delegation, delegationCid: 'wrong' }, bindings)).rejects.toMatchObject({ code: 'SERVER' });
  }
  expect(padded).toBeGreaterThan(0);
});
