// Facts a reviewer needs on a host approval: which space is being hosted and
// which node key (`did:key`) receives it, plus the check that tells whether a
// known TinyCloud node holds that key for that space.
//
// A host SIWE has no `Expiration Time`, its `URI:` line is the node's
// `did:key`, and its ReCap grants `tinycloud.space/host` on `<space>/space`.
// A node's key for a space is derived per space, so the only way to
// recognise it is to ask the known node for its key for that space and
// compare.
//
// Everything here is display and recognition only. It never decides what is
// permitted or signed.

import type { CapabilityReviewModel } from "./model.js";
import { SPACE_SERVICES } from "./core-operations.js";

export const SPACE_HOST_ABILITY = "tinycloud.space/host";

const SPACE_ID = /^tinycloud:pkh:eip155:(\d+):(0x[a-fA-F0-9]{40}):([A-Za-z0-9][A-Za-z0-9._-]{0,63})$/;
const SPACE_NAME_DISPLAY = /^[a-z0-9][a-z0-9-]*$/;
const DID_KEY = /^did:key:z[1-9A-HJ-NP-Za-km-z]{20,100}(?:#[A-Za-z0-9._:-]{1,120})?$/;
const URI_LINE = /^URI: ?(.*)$/gm;

export interface HostedSpace {
  /** Full space id, exactly as the ReCap names it. */
  spaceId: string;
  /** Short name, only when it is plain lowercase letters, digits and `-`. */
  spaceName: string | null;
}

export interface SpaceHostFacts {
  spaces: HostedSpace[];
  /**
   * The SIWE `URI:` line when it is exactly one `did:key`, else null (no
   * `URI:` line, more than one, or another kind of URI).
   */
  peerDid: string | null;
}

export function isSpaceId(value: string): boolean {
  return SPACE_ID.test(value);
}

/** The space's short name when it is plain enough to show as a label. */
export function spaceDisplayName(spaceId: string): string | null {
  const name = SPACE_ID.exec(spaceId)?.[3];
  return name !== undefined && SPACE_NAME_DISPLAY.test(name) ? name : null;
}

/**
 * Shorten a space id without touching its prefix or its name:
 * `tinycloud:pkh:eip155:1:0x1111…1111:default`. Anything that is not a
 * well-formed space id is returned whole.
 */
export function abbreviateSpaceId(spaceId: string): string {
  const match = SPACE_ID.exec(spaceId);
  if (!match) return spaceId;
  const [, chain, address, name] = match;
  return `tinycloud:pkh:eip155:${chain}:${address!.slice(0, 6)}…${address!.slice(-4)}:${name}`;
}

/** Shorten a `did:key` keeping its head and tail: `did:key:z6Mkj8Zn…rPteD25`. */
export function abbreviateDid(did: string): string {
  const [base = did] = did.split("#");
  return base.length <= 26 ? base : `${base.slice(0, 16)}…${base.slice(-7)}`;
}

function readPeerDid(message: string): string | null {
  const lines: string[] = [];
  for (const match of message.matchAll(URI_LINE)) {
    lines.push((match[1] ?? "").replace(/\r$/, ""));
  }
  if (lines.length !== 1) return null;
  const value = lines[0]!;
  return DID_KEY.test(value) ? value : null;
}

/**
 * The spaces a request asks the signer to host, and the node key named by the
 * `URI:` line. Read from `model.rawMessage`, the bytes that are signed. Null
 * when no selected grant holds `tinycloud.space/host` on one of the signer's
 * own spaces.
 */
export function readSpaceHostFacts(
  model: CapabilityReviewModel,
  selectedActionIds?: ReadonlySet<string>,
): SpaceHostFacts | null {
  if (model.protocol !== "tinycloud-siwe-recap") return null;
  const spaces = new Map<string, HostedSpace>();
  for (const grant of model.permissions) {
    if (!SPACE_SERVICES.has(grant.service) || grant.ownedBySelf === false) continue;
    const hosts = grant.actions.some(
      (action) =>
        action.ability === SPACE_HOST_ABILITY &&
        (selectedActionIds === undefined || selectedActionIds.has(action.id)),
    );
    if (!hosts || spaces.has(grant.space)) continue;
    spaces.set(grant.space, { spaceId: grant.space, spaceName: spaceDisplayName(grant.space) });
  }
  if (spaces.size === 0) return null;
  return { spaces: [...spaces.values()], peerDid: readPeerDid(model.rawMessage) };
}

/** Two node keys are the same key: `#fragment` ignored, otherwise exact. */
export function samePeerDid(left: string, right: string): boolean {
  const strip = (value: string) => value.trim().split("#")[0]!;
  const a = strip(left);
  const b = strip(right);
  return a.startsWith("did:key:") && a === b;
}

export type HostPeerRecognition =
  | { kind: "known"; origin: string }
  | { kind: "other" };

export const HOST_PEER_CHECK_TIMEOUT_MS = 5_000;

export interface RecognizeHostPeerInput {
  spaces: readonly string[];
  peerDid: string;
  /** The configured known node origins. The only origins ever contacted. */
  nodeOrigins: readonly string[];
  /**
   * Ask `origin` for its key for `spaceId` (`GET /peer/generate/{space}`).
   * Resolves the key text, or null when the node did not answer with one.
   */
  fetchPeer: (origin: string, spaceId: string, signal: AbortSignal) => Promise<string | null>;
  timeoutMs?: number;
}

/**
 * `known` when one configured node origin answers, for every hosted space,
 * with the key the request names. Everything else (no answer, timeout, other
 * key, malformed ids) is `other`. The origin reported is always the configured
 * one that matched, in configured order.
 */
export async function recognizeHostPeer(input: RecognizeHostPeerInput): Promise<HostPeerRecognition> {
  const { spaces, peerDid, nodeOrigins, fetchPeer } = input;
  const timeoutMs = input.timeoutMs ?? HOST_PEER_CHECK_TIMEOUT_MS;
  if (spaces.length === 0 || !DID_KEY.test(peerDid) || !spaces.every(isSpaceId)) {
    return { kind: "other" };
  }

  const controller = new AbortController();
  let cancelTimer = () => {};
  const expired = new Promise<null>((resolve) => {
    const id = setTimeout(() => {
      controller.abort();
      resolve(null);
    }, timeoutMs);
    cancelTimer = () => clearTimeout(id);
  });

  const answers = async (origin: string, spaceId: string): Promise<boolean> => {
    try {
      const answer = await fetchPeer(origin, spaceId, controller.signal);
      return typeof answer === "string" && samePeerDid(answer, peerDid);
    } catch {
      return false;
    }
  };
  const originMatches = async (origin: string): Promise<boolean> =>
    (await Promise.all(spaces.map((spaceId) => answers(origin, spaceId)))).every(Boolean);

  try {
    const results = await Promise.race([
      Promise.all(nodeOrigins.map(originMatches)),
      expired,
    ]);
    if (results === null) return { kind: "other" };
    const index = results.findIndex(Boolean);
    return index >= 0 ? { kind: "known", origin: nodeOrigins[index]! } : { kind: "other" };
  } finally {
    cancelTimer();
    controller.abort();
  }
}
