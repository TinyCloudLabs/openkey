// Recognises the node key on a host approval (`readSpaceHostFacts`) against the
// TinyCloud nodes OpenKey knows. The known list is the one `/delegate` uses
// (`KNOWN_NODE_ORIGINS`, which mirrors the API's trusted bootstrap hosts, plus
// any `VITE_DELEGATE_NODE_ORIGINS`). Only those origins are ever contacted.

import {
  recognizeHostPeer,
  type HostPeerRecognition,
  type SpaceHostFacts,
} from '@openkey/capability-review';
import { KNOWN_NODE_ORIGINS, isCanonicalHttpsOrigin, withConfiguredEntries } from './delegate-link-policy';

/** What the approval view shows about the node key. */
export type PeerRecognitionState =
  | { state: 'checking' }
  | { state: 'known'; origin: string }
  | { state: 'other' };

const MAX_PEER_ANSWER_LENGTH = 200;

/** The configured known node origins (built-in plus the configured extras). */
export function knownNodeOrigins(extra: string | undefined): string[] {
  return withConfiguredEntries(KNOWN_NODE_ORIGINS, extra, isCanonicalHttpsOrigin);
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

/** Look the node key up. Anything but a match is `other`. */
export function recognizeFacts(
  facts: SpaceHostFacts,
  extraOrigins: string | undefined,
): Promise<HostPeerRecognition> {
  if (facts.peerDid === null) return Promise.resolve({ kind: 'other' });
  return recognizeHostPeer({
    spaces: facts.spaces.map((space) => space.spaceId),
    peerDid: facts.peerDid,
    nodeOrigins: knownNodeOrigins(extraOrigins),
    fetchPeer: fetchNodePeer,
  });
}

/**
 * Start the lookup for `facts` and report each state. Returns a cleanup that
 * drops a late answer. A request with no node key to check reports nothing.
 */
export function watchHostPeer(
  facts: SpaceHostFacts | null,
  extraOrigins: string | undefined,
  report: (next: PeerRecognitionState | null) => void,
): () => void {
  if (facts === null || facts.peerDid === null) {
    report(null);
    return () => {};
  }
  let current = true;
  report({ state: 'checking' });
  void recognizeFacts(facts, extraOrigins).then((result) => {
    if (current) report(result.kind === 'known' ? { state: 'known', origin: result.origin } : { state: 'other' });
  });
  return () => {
    current = false;
  };
}
