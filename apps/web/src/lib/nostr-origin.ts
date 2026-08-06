// Strict origin + relay URL parsing for the OpenKey Nostr widget.
//
// Mirrors the server-side validation in apps/api/src/routes/nostr-keys.ts
// (`parseClientOrigin` / `parseRelayUrl`) so the widget only ever targets or
// accepts postMessage traffic against an exact, canonical http(s) origin -
// never a wildcard (`*`) targetOrigin, and never a path/query/credentialed
// URL. Deliberately duplicated rather than shared: the web app and API are
// separate deployables and cannot import from one another.

/** A parseable absolute http(s) origin with no path, query, credentials, or fragment. */
export function parseCanonicalOrigin(value: string | null | undefined): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  if (url.username || url.password) return null;
  if (url.pathname !== '/' && url.pathname !== '') return null;
  if (url.search || url.hash) return null;
  return url.origin;
}

/**
 * Validates the scheme but returns the caller's original string (not
 * `URL#toString()`, which appends a trailing slash to host-only URLs and
 * would silently break exact-match comparison against the relay tag on a
 * signed kind:22242 event, e.g. "ws://host:port" vs "ws://host:port/").
 */
export function parseNostrRelayUrl(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== 'ws:' && url.protocol !== 'wss:') return null;
  return value;
}

/** Unsigned/signed NIP-01 event shape - just enough to read the `relay` tag. */
export interface NostrEventTagsLike {
  tags: string[][];
}

/** Extract the single `relay` tag value from a kind:22242 (NIP-42) event, if present. */
export function extractRelayTag(event: NostrEventTagsLike): string | null {
  const relayTag = event.tags.find((t) => Array.isArray(t) && t[0] === 'relay');
  return relayTag?.[1] ?? null;
}
