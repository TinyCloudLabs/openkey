import type { Hex } from 'viem';
import { createTeeClient, unseal } from '@openkey/tee';
import { deriveKeyForRecord } from './key-sealing';
import { invalidSiweMessage } from './siwe-message-refusal';

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
  // TC-3826 backstop: every route refuses such a SIWE with a 400 first.
  if (invalidSiweMessage(message)) throw new Error('refusing to sign a SIWE with a forbidden character');
  const privateKey = await unsealManagedKey(key, sealedBlob);
  const { createWalletFromPrivateKey } = await import('@openkey/tee');
  return createWalletFromPrivateKey(privateKey).signMessage({ message });
}
