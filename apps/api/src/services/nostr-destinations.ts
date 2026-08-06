// Destination binding for Nostr signing grants.
//
// A grant's `relayUrl` (a ws(s):// URL approved by the user) is the single
// destination anchor for every destination-bound kind. The Buzz web client
// derives all of its authenticated HTTP surfaces from the relay URL, and
// this module mirrors those exact derivations so a grant approved for one
// relay can never authorize a signed challenge or HTTP token for an
// unrelated destination:
//
//  - kind 22242 (NIP-42): the event's `relay` tag must equal the granted
//    relay URL exactly (string comparison, matching the relay's own check).
//  - kind 24242 (Blossom): the event's `server` tag must equal the host
//    authority of the relay mapped to http(s) - lowercase hostname
//    (bracketed for IPv6) plus any non-default port, no scheme or path.
//  - kind 27235 (NIP-98): the event's `u` URL must live on the relay's
//    http(s) surface, on one of the fixed Buzz journey paths (invite
//    minting/claiming keeps the relay URL's path prefix; moderation reads
//    are rooted at the origin).
//
// ws: maps to http: and wss: to https: - both directions are deterministic,
// so the binding loses nothing across the protocol change.

/** Map a ws(s) relay URL to its http(s) origin (no path, query, or hash). */
export function relayHttpOrigin(relayUrl: string): string | null {
  let url: URL;
  try {
    url = new URL(relayUrl);
  } catch {
    return null;
  }
  if (url.protocol === 'ws:') url.protocol = 'http:';
  else if (url.protocol === 'wss:') url.protocol = 'https:';
  else return null;
  return url.origin;
}

/**
 * Map a ws(s) relay URL to the http(s) base Buzz uses for invite endpoints:
 * scheme swapped, hash stripped, path and query KEPT, trailing slash
 * stripped (`relayHttpBaseUrl` in buzz/web invites.ts).
 */
export function relayInvitesHttpBase(relayUrl: string): string | null {
  let url: URL;
  try {
    url = new URL(relayUrl);
  } catch {
    return null;
  }
  if (url.protocol === 'ws:') url.protocol = 'http:';
  else if (url.protocol === 'wss:') url.protocol = 'https:';
  else return null;
  url.hash = '';
  return url.toString().replace(/\/$/, '');
}

/**
 * The Blossom `server` tag Buzz derives from a relay URL: lowercase
 * hostname (bracketed for IPv6) plus the port when it is not the mapped
 * http(s) scheme's default (`serverAuthority` in buzz/web media.ts).
 */
export function relayServerAuthority(relayUrl: string): string | null {
  let url: URL;
  try {
    url = new URL(relayUrl);
  } catch {
    return null;
  }
  if (url.protocol === 'ws:') url.protocol = 'http:';
  else if (url.protocol === 'wss:') url.protocol = 'https:';
  else return null;
  const host = url.hostname.includes(':') ? `[${url.hostname}]` : url.hostname;
  const defaultPort =
    (url.protocol === 'https:' && url.port === '443') ||
    (url.protocol === 'http:' && url.port === '80');
  return `${host}${url.port && !defaultPort ? `:${url.port}` : ''}`.toLowerCase();
}

const MODERATION_PATHS = new Set(['/moderation/reports', '/moderation/audit', '/moderation/restricted']);
const MODERATION_QUERY_KEYS = new Set(['status', 'limit']);
const MODERATION_STATUS_RE = /^[a-z]{1,32}$/;
const MODERATION_LIMIT_RE = /^(0|[1-9][0-9]{0,3})$/;

/**
 * Is `uValue` a NIP-98 `u` URL for one of the Buzz journeys this custody
 * slice supports, bound to the granted relay?
 *
 *  - POST journeys: invite mint (`{invitesBase}/api/invites`) and invite
 *    claim (`{invitesBase}/api/invites/claim`), no query, no hash.
 *  - GET journeys: moderation reads on the relay's http(s) origin
 *    (`/moderation/reports`, `/moderation/audit`, `/moderation/restricted`)
 *    with only bounded `status`/`limit` query parameters.
 */
export function isAllowedNip98Url(uValue: string, method: 'GET' | 'POST', grantRelayUrl: string): boolean {
  let u: URL;
  try {
    u = new URL(uValue);
  } catch {
    return false;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  if (u.username || u.password || u.hash) return false;

  if (method === 'POST') {
    const base = relayInvitesHttpBase(grantRelayUrl);
    if (!base) return false;
    if (u.search) return false;
    return uValue === `${base}/api/invites` || uValue === `${base}/api/invites/claim`;
  }

  const origin = relayHttpOrigin(grantRelayUrl);
  if (!origin) return false;
  if (u.origin !== origin) return false;
  if (!MODERATION_PATHS.has(u.pathname)) return false;
  for (const [param, value] of u.searchParams) {
    if (!MODERATION_QUERY_KEYS.has(param)) return false;
    if (param === 'status' && !MODERATION_STATUS_RE.test(value)) return false;
    if (param === 'limit' && !MODERATION_LIMIT_RE.test(value)) return false;
  }
  return true;
}
