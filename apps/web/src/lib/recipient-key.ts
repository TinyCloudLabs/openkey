const DID_KEY_PREFIX = 'did:key:';
/** Every Ed25519 `did:key` id starts with this, so it tells keys apart by nothing. */
const ED25519_ID_PREFIX = 'z6Mk';

/**
 * The short form of the key an approval request's access goes to. The `did:key:` prefix and any fragment are left off.
 * For an Ed25519 key (an id that starts with `z6Mk`) that prefix is left off too: the 6 characters after it, an
 * ellipsis and the last 4 (`z6MkhaXgBZ…2doK` is `haXgBZ…2doK`). Any other id keeps its first 6 and last 4. What is left
 * is shown whole when it is 10 characters or fewer, since abbreviating would hide nothing.
 */
export function shortRecipientKey(key: string): string {
  const [base = key] = key.split('#');
  const id = base.startsWith(DID_KEY_PREFIX) ? base.slice(DID_KEY_PREFIX.length) : base;
  const rest = id.startsWith(ED25519_ID_PREFIX) ? id.slice(ED25519_ID_PREFIX.length) : id;
  return rest.length <= 10 ? rest : `${rest.slice(0, 6)}…${rest.slice(-4)}`;
}
