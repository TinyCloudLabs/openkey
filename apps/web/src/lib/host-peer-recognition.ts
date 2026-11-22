// Recognises the node key on a host approval (`readSpaceHostFacts`) against the
// TinyCloud nodes OpenKey knows. The known list is the one `/delegate` uses
// (`KNOWN_NODE_ORIGINS`, which mirrors the API's trusted bootstrap hosts, plus
// any `VITE_DELEGATE_NODE_ORIGINS`). Only those origins are ever contacted, and
// only the one the request names (TC-2309): a request that names another node,
// a local one included, makes no lookup at all.

import {
  recognizeHostPeer,
  type HostPeerRecognition,
  type SpaceHostFacts,
} from '@openkey/capability-review';
import { KNOWN_NODE_ORIGINS, isCanonicalHttpsOrigin, withConfiguredEntries } from './delegate-link-policy';

/**
 * What the approval view shows about the node key. `failed` is a lookup that got no key back from the node for some
 * space (no answer, an error status, an oversized answer, a timeout); `other` is every other non-match.
 */
export type PeerRecognitionState =
  | { state: 'checking' }
  | { state: 'known'; origin: string }
  | { state: 'other' }
  | { state: 'failed' };

/** The result of one lookup: the shared recognition, or `failed` when a node asked gave no key back. */
export type NodeCheck = HostPeerRecognition | { kind: 'failed' };

/**
 * TC-3853: whether `spaceId` names the `credentials` space, parsed as the node parses a space id (the name is what
 * follows the last `:`) and compared exactly, as its credentials policy does (`name().as_str() != "credentials"`).
 */
export function isCredentialsSpaceId(spaceId: string): boolean {
  return spaceId.slice(spaceId.lastIndexOf(':') + 1) === 'credentials';
}

const MAX_PEER_ANSWER_LENGTH = 200;

/** The one node a host approval is checked against when the request names none (both production names are the same node). */
export const DEFAULT_NODE_ORIGIN = 'https://node.tinycloud.xyz';

// Printable ASCII, no space; checked before lowercasing, as the API does (services/tinycloud-hosts.ts): String#toLowerCase
// maps some non-ASCII (U+212A KELVIN SIGN -> "k") onto ASCII.
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;

/** The configured known node origins (built-in plus the configured extras). */
export function knownNodeOrigins(extra: string | undefined): string[] {
  return withConfiguredEntries(KNOWN_NODE_ORIGINS, extra, isCanonicalHttpsOrigin);
}

/**
 * The origins a host approval may ask for the node key: the default node when the request names no host; the
 * named origin when it is exactly a known origin (any ASCII case, one optional trailing slash); otherwise none.
 * The host string itself must equal an allowlisted origin: the URL parser never makes an input acceptable, so
 * userinfo, a port, a path, a query, http, an encoded or look-alike host and loopback all give none.
 */
export function probeOriginsFor(host: string | null | undefined, extraOrigins: string | undefined): string[] {
  if (host === undefined || host === null || host === '') return [DEFAULT_NODE_ORIGIN];
  if (typeof host !== 'string' || !PRINTABLE_ASCII.test(host)) return [];
  const candidate = (host.endsWith('/') ? host.slice(0, -1) : host).toLowerCase();
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return [];
  }
  if (url.protocol !== 'https:' || url.origin !== candidate) return [];
  return knownNodeOrigins(extraOrigins).includes(candidate) ? [candidate] : [];
}

/** `GET {origin}/peer/generate/{space}`: the node's key for that space, or null. */
export async function fetchNodePeer(origin: string, spaceId: string, signal: AbortSignal): Promise<string | null> {
  const response = await fetch(`${origin}/peer/generate/${encodeURIComponent(spaceId)}`, {
    signal,
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  if (!response.ok) return null;
  const text = await response.text();
  return text.length <= MAX_PEER_ANSWER_LENGTH ? text.trim() : null;
}

/**
 * Look the node key up. A match is `known`; a lookup where some node asked gave no key back (no answer, an error
 * status, an oversized answer, a timeout) is `failed`; anything else is `other`.
 */
export async function recognizeFacts(
  facts: SpaceHostFacts,
  extraOrigins: string | undefined,
  host?: string | null,
): Promise<NodeCheck> {
  const nodeOrigins = probeOriginsFor(host, extraOrigins);
  if (facts.peerDid === null || nodeOrigins.length === 0) return { kind: 'other' };
  let asked = 0;
  let answered = 0;
  const result = await recognizeHostPeer({
    spaces: facts.spaces.map((space) => space.spaceId),
    peerDid: facts.peerDid,
    nodeOrigins,
    fetchPeer: async (origin, spaceId, signal) => {
      asked += 1;
      const answer = await fetchNodePeer(origin, spaceId, signal);
      if (answer !== null) answered += 1;
      return answer;
    },
  });
  // A lookup still in flight when the check ended (the timeout) also gave no key back.
  return result.kind === 'other' && answered < asked ? { kind: 'failed' } : result;
}

/**
 * Start the lookup for `facts` and report each state. Returns a cleanup that
 * drops a late answer. A request with no node key to check reports nothing.
 */
export function watchHostPeer(
  facts: SpaceHostFacts | null,
  extraOrigins: string | undefined,
  report: (next: PeerRecognitionState | null) => void,
  host?: string | null,
): () => void {
  if (facts === null || facts.peerDid === null) {
    report(null);
    return () => {};
  }
  // A host the page does not trust is never contacted: nothing to look up, so the answer is known at once.
  if (probeOriginsFor(host, extraOrigins).length === 0) {
    report({ state: 'other' });
    return () => {};
  }
  let current = true;
  report({ state: 'checking' });
  void recognizeFacts(facts, extraOrigins, host).then((result) => {
    if (!current) return;
    report(result.kind === 'known' ? { state: 'known', origin: result.origin } : { state: result.kind });
  });
  return () => {
    current = false;
  };
}
