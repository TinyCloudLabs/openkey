const DID_KEY_PREFIX = 'did:key:';

/**
 * The short form of the key an approval request's access goes to: the first 6 and last 4 characters of its id, as the
 * signing key's address is shortened (`0xd559…f412`). The `did:key:` prefix and any fragment are left off, since every
 * such key starts with them. An id of 10 characters or fewer is shown whole.
 */
export function shortRecipientKey(key: string): string {
  const [base = key] = key.split('#');
  const id = base.startsWith(DID_KEY_PREFIX) ? base.slice(DID_KEY_PREFIX.length) : base;
  return id.length <= 10 ? id : `${id.slice(0, 6)}…${id.slice(-4)}`;
}
