import type { Hex } from 'viem';
import { createTeeClient, unseal } from '@openkey/tee';
import { deriveKeyForRecord } from './key-sealing';
import { namesIssuerStatement } from './org-issuer-statement';

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
  // K1 D3: an issuer statement is signable only through the organization route.
  // Refused before unseal. The prefix is the one delegate.ts maps to a 400.
  if (namesIssuerStatement(message)) {
    throw new Error('message_rejected:issuer_statement_not_personal');
  }
  const privateKey = await unsealManagedKey(key, sealedBlob);
  const { createWalletFromPrivateKey } = await import('@openkey/tee');
  return createWalletFromPrivateKey(privateKey).signMessage({ message });
}
