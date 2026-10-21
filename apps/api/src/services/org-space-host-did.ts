import { isEd25519DidKey } from './org-space-signing';
import { nodeFetchPeerId, trustedTinyCloudBootstrapHost } from './tinycloud-bootstrap';

// The node stages one host DID per space. A space-host URI must equal it (org-space-signing.ts).
// Only successes are cached, for at most this long; a failure is never cached.
export const ORG_SPACE_HOST_DID_TTL_MS = 60 * 1000;

export type OrgSpaceHostDidFetch = (host: string, spaceId: string) => Promise<string>;

export type OrgSpaceHostDidResolver = (host: string, spaceId: string) => Promise<string | null>;

// Resolves to the node's ed25519 did:key for the space, or null. Null covers every failure:
// network error, timeout, non-ed25519 or malformed body. Callers treat null as unavailable.
export function createOrgSpaceHostDidResolver(deps: {
  fetchPeerId: OrgSpaceHostDidFetch;
  now?: () => number;
  ttlMs?: number;
}): OrgSpaceHostDidResolver {
  const now = deps.now ?? Date.now;
  const ttlMs = deps.ttlMs ?? ORG_SPACE_HOST_DID_TTL_MS;
  const cache = new Map<string, { did: string; expiresAt: number }>();
  const inFlight = new Map<string, Promise<string | null>>();

  return (host, spaceId) => {
    const key = `${host}\n${spaceId}`;
    const cached = cache.get(key);
    if (cached && cached.expiresAt > now()) return Promise.resolve(cached.did);

    const pending = inFlight.get(key);
    if (pending) return pending;

    const request = Promise.resolve()
      .then(() => deps.fetchPeerId(host, spaceId))
      .then(
        (body) => {
          const did = body.trim();
          if (!isEd25519DidKey(did)) return null;
          cache.set(key, { did, expiresAt: now() + ttlMs });
          return did;
        },
        () => null,
      )
      .finally(() => inFlight.delete(key));
    inFlight.set(key, request);
    return request;
  };
}

const defaultResolver = createOrgSpaceHostDidResolver({ fetchPeerId: nodeFetchPeerId });
let activeResolver: OrgSpaceHostDidResolver = defaultResolver;

// Test hook, same shape as setTinyCloudBootstrapExecutorForTests. A new resolver starts with an empty cache.
export function setOrgSpaceHostDidFetchForTests(fetchPeerId?: OrgSpaceHostDidFetch): void {
  activeResolver = fetchPeerId ? createOrgSpaceHostDidResolver({ fetchPeerId }) : defaultResolver;
}

// The host DID for an org space, via the trusted bootstrap host. Null when no trusted host
// is configured or the node gives no valid DID.
export async function resolveOrgSpaceHostDid(spaceId: string): Promise<string | null> {
  let host: string;
  try {
    host = trustedTinyCloudBootstrapHost();
  } catch {
    return null;
  }
  return activeResolver(host, spaceId);
}
