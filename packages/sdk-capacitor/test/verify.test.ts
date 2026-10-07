import { expect, mock, test } from 'bun:test';
import { verifyTinyCloudDelegation } from '../src/verify';
import type { TinyCloudDelegation } from '@openkey/core';

let cidCalls = 0;
mock.module('@tinycloud/web-sdk', () => ({
  BrowserWasmBindings: class {
    async ensureInitialized() {}
    siweToDelegationHeaders({ siwe, signature }: { siwe: string; signature: string }) {
      expect(siwe).toBe('exact siwe');
      expect(signature).toBe('0xsigned');
      return { Authorization: 'Bearer AQID' };
    }
    computeCid(bytes: Uint8Array, codec: bigint) {
      cidCalls++;
      expect([...bytes]).toEqual([1, 2, 3]);
      expect(codec).toBe(0x55n);
      return 'bafyverified';
    }
  },
}));

const delegation = {
  siwe: 'exact siwe', signature: '0xsigned',
  delegationHeader: { Authorization: 'Bearer AQID' },
  delegationCid: 'bafyverified',
} as TinyCloudDelegation;

test('TinyCloud WASM reproduces both header and CID before storage', async () => {
  await verifyTinyCloudDelegation(delegation);
  expect(cidCalls).toBe(1);
  await expect(verifyTinyCloudDelegation({ ...delegation, delegationHeader: { Authorization: 'Bearer wrong' } }))
    .rejects.toMatchObject({ code: 'SERVER' });
  await expect(verifyTinyCloudDelegation({ ...delegation, delegationCid: 'wrong' }))
    .rejects.toMatchObject({ code: 'SERVER' });
});
