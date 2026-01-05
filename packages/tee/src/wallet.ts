// Viem wallet integration for TEE-derived keys
import { privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts';
import { type Hex } from 'viem';

/**
 * Create a Viem account from a private key
 * Use this after unsealing the private key from TEE storage
 */
export function createWalletFromPrivateKey(privateKey: Hex): PrivateKeyAccount {
  return privateKeyToAccount(privateKey);
}

/**
 * Generate a new random private key
 * Returns hex-encoded private key suitable for Ethereum
 */
export function generatePrivateKey(): Hex {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return `0x${Buffer.from(randomBytes).toString('hex')}` as Hex;
}

/**
 * Get address from private key without creating full account
 */
export function getAddressFromPrivateKey(privateKey: Hex): Hex {
  const account = privateKeyToAccount(privateKey);
  return account.address;
}
