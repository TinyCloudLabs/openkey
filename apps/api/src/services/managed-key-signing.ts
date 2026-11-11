import type { Hex } from 'viem';
import { createTeeClient } from '@openkey/tee';
import { unsealKeyForRecord, type SealingRecord } from './key-sealing';

const tee = createTeeClient();
export async function unsealManagedKey(
  key: SealingRecord,
  sealedBlob: string,
): Promise<Hex> {
  return unsealKeyForRecord(tee, key, sealedBlob) as Promise<Hex>;
}
export async function signManagedKey(
  key: SealingRecord,
  sealedBlob: string,
  message: string,
): Promise<Hex> {
  const privateKey = await unsealManagedKey(key, sealedBlob);
  const { createWalletFromPrivateKey } = await import('@openkey/tee');
  return createWalletFromPrivateKey(privateKey).signMessage({ message });
}
