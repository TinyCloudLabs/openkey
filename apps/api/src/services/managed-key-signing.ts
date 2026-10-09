import type { Hex } from 'viem';
import { createTeeClient, unseal } from '@openkey/tee';
import { deriveKeyForRecord } from './key-sealing';

const tee = createTeeClient();
export async function unsealManagedKey(
  key: { userId: string | null; sealingContext?: string | null },
  sealedBlob: string,
): Promise<Hex> {
  const sealingKey = await deriveKeyForRecord(tee, key);
  return unseal(sealedBlob, sealingKey) as Promise<Hex>;
}
export async function signManagedKey(
  key: { userId: string | null; sealingContext?: string | null },
  sealedBlob: string,
  message: string,
): Promise<Hex> {
  const privateKey = await unsealManagedKey(key, sealedBlob);
  const { createWalletFromPrivateKey } = await import('@openkey/tee');
  return createWalletFromPrivateKey(privateKey).signMessage({ message });
}
