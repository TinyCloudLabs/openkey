import type { EthereumKey } from './api';

/**
 * The key `/delegate` selects without showing the picker (TC-659): the key
 * the CLI requested when the request names a wallet, otherwise the user's
 * only key. Returns null when the user must choose.
 */
export function autoSelectKey(keys: EthereumKey[], expectedAddress: string | null): EthereumKey | null {
  if (expectedAddress) {
    return keys.find((key) => key.address.toLowerCase() === expectedAddress) ?? null;
  }
  return keys.length === 1 ? keys[0]! : null;
}
