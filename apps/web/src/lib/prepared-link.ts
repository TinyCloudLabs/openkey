const MAX_PREPARED_LINK_BYTES = 8192;

/** URL serialization percent-encodes non-ASCII; the fragment is base64url ASCII. */
export function fitsPreparedLinkBudget(url: { origin: string; pathname: string }, fragment: string): boolean {
  return url.origin.length + url.pathname.length + fragment.length <= MAX_PREPARED_LINK_BYTES;
}
