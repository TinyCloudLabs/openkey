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

/** Event shape for relay derivation - tags plus the kind that scopes them. */
export interface NostrEventKindTagsLike extends NostrEventTagsLike {
  kind: number;
}

function tagValue(event: NostrEventTagsLike, name: string): string | null {
  const tag = event.tags.find((t) => Array.isArray(t) && t[0] === name);
  return typeof tag?.[1] === 'string' ? tag[1] : null;
}

/**
 * The ws(s) relay URL a grant for this destination-bound event should be
 * bound to. Prefers the client's `relayUrl` hint (validated, never trusted
 * to widen anything - the API independently checks the signed event's own
 * destination against the grant). Falls back to deriving from the event:
 *
 *  - 22242: the `relay` tag is the relay URL itself (hint ignored - the
 *    event names its destination exactly).
 *  - 27235: the `u` URL maps deterministically back (https->wss, http->ws);
 *    POST journeys strip the fixed invite suffix, GET journeys use the
 *    origin.
 *  - 24242: the `server` tag is a bare authority with no scheme, so the
 *    hint is required; returns null without one.
 *
 * Returns null when no trustworthy relay URL can be determined - the
 * approval fails closed rather than guessing a destination.
 */
export function deriveRelayUrlForGrant(
  event: NostrEventKindTagsLike,
  relayUrlHint?: unknown,
): string | null {
  if (event.kind === 22242) {
    return parseNostrRelayUrl(extractRelayTag(event));
  }
  const hint = parseNostrRelayUrl(relayUrlHint);
  if (hint) return hint;
  if (event.kind === 27235) {
    const u = tagValue(event, 'u');
    const method = tagValue(event, 'method');
    if (!u) return null;
    let url: URL;
    try {
      url = new URL(u);
    } catch {
      return null;
    }
    if (url.protocol === 'https:') url.protocol = 'wss:';
    else if (url.protocol === 'http:') url.protocol = 'ws:';
    else return null;
    if (method === 'GET') return parseNostrRelayUrl(url.origin);
    url.search = '';
    url.hash = '';
    const withoutSuffix = url.toString().replace(/\/api\/invites(\/claim)?$/, '');
    if (withoutSuffix === url.toString()) return null;
    return parseNostrRelayUrl(withoutSuffix.replace(/\/$/, '') || null);
  }
  return null;
}
