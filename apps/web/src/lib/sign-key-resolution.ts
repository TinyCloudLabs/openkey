// A sign request that names no key (the app never connected, or lost its connection) is answered with a key of the
// signed-in account only when exactly one fits; otherwise the owner chooses, or sees that none can sign. It never
// guesses: a SIWE names its signer, so only that address fits. Resolving a key only selects it: the owner still
// reviews and approves the exact message on the same screen as for a named key.
import { isSiweShaped } from '@openkey/capability-review';
import type { EthereumKey } from '$lib/api';

export type SigningKeyResolution =
  | { kind: 'resolved'; key: EthereumKey }
  | { kind: 'choose'; keys: EthereumKey[] }
  | { kind: 'none' };

/** Code of the error a sign request is answered with when no key of the account can sign it. */
export const NO_KEY_ERROR = {
  code: 'NO_KEY',
  message: 'No key of the signed-in OpenKey account can sign this request.',
} as const;

const SIWE_HEADER = / wants you to sign in with your Ethereum account:$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** The lower-cased signer address of a SIWE message (the line after its header), or null when it names none. */
function siweSigner(message: string): string | null {
  const lines = message.split(/\r?\n/);
  const header = lines.findIndex((line) => SIWE_HEADER.test(line));
  const address = header < 0 ? undefined : lines[header + 1];
  return address !== undefined && ADDRESS.test(address) ? address.toLowerCase() : null;
}

/**
 * `keys` is the signed-in account's own key list (owner-scoped on the server). Archived keys and linked wallets
 * (EXTERNAL: OpenKey holds no private key) never sign here.
 */
export function resolveSigningKey(keys: readonly EthereumKey[], message: string): SigningKeyResolution {
  let candidates = keys.filter((key) => !key.archivedAt && key.keyType === 'MANAGED');
  if (isSiweShaped(message)) {
    const signer = siweSigner(message);
    candidates = signer ? candidates.filter((key) => key.address.toLowerCase() === signer) : [];
  }
  if (candidates.length === 1) return { kind: 'resolved', key: candidates[0]! };
  return candidates.length > 1 ? { kind: 'choose', keys: candidates } : { kind: 'none' };
}
