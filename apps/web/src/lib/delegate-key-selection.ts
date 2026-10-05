import type { EthereumKey } from './api';

/** The user's primary key, when `keys` holds one. */
export function primaryKey(keys: EthereumKey[]): EthereumKey | null {
  return keys.find((key) => key.isPrimary === true) ?? null;
}

/**
 * The key `/delegate` selects without showing the picker (TC-659, TC-703):
 * the key the CLI requested when the request names a wallet, otherwise the
 * user's primary key, otherwise the user's only key. Returns null when the
 * user must choose.
 */
export function autoSelectKey(keys: EthereumKey[], expectedAddress: string | null): EthereumKey | null {
  if (expectedAddress) {
    return keys.find((key) => key.address.toLowerCase() === expectedAddress) ?? null;
  }
  return primaryKey(keys) ?? (keys.length === 1 ? keys[0]! : null);
}

/**
 * How the `/delegate` picker lists keys (TC-703). When the request names no
 * wallet and the user has a primary key, the picker offers the primary key
 * and keeps every other key behind an explicit "Use a different key" step:
 * each key is a separate account owner with its own data. Otherwise (the
 * request names a wallet, or there is no primary key) every key is listed.
 */
export type KeyPickerLayout =
  | { kind: 'primary'; primary: EthereumKey; others: EthereumKey[] }
  | { kind: 'list'; keys: EthereumKey[] };

export function keyPickerLayout(keys: EthereumKey[], expectedAddress: string | null): KeyPickerLayout {
  const primary = expectedAddress ? null : primaryKey(keys);
  if (!primary) return { kind: 'list', keys };
  return { kind: 'primary', primary, others: keys.filter((key) => key !== primary) };
}
