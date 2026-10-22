// Strict parser and containment for encryption resources (CONTRACT.md v0.2
// §2-§3). Shape only: the owner DID is not verified and its casing is kept
// exactly as written. Parsing never throws; anything outside the grammar
// returns null.

export const ENCRYPTION_URN_PREFIX = "urn:tinycloud:encryption:";

/** Maximum byte length of a key path, including a prefix's trailing `/`. */
const MAX_KEY_PATH_BYTES = 255;

// Owner and network are ASCII printable, never containing `/` or whitespace.
// The owner may contain `:` (did:pkh:eip155:1:0x...); the network may not.
const BARE_NETWORK_RE = /^(did:[!-.0-9:;-~]+):([!-.0-9;-~]+)$/;

const SEGMENT = "[a-z0-9][a-z0-9._-]{0,63}";
const KEY_RE = new RegExp(
  `^(did:[!-.0-9:;-~]+):([!-.0-9;-~]+)/(${SEGMENT}(?:/${SEGMENT}){0,7}/?)$`,
);

export type EncryptionResource =
  | { kind: "network"; ownerDid: string; network: string }
  | {
      kind: "key" | "prefix";
      ownerDid: string;
      network: string;
      /** Path exactly as written; a prefix keeps its single trailing `/`. */
      keyPath: string;
    };

/**
 * Parse `urn:tinycloud:encryption:<owner>:<network>` (network) or
 * `urn:tinycloud:encryption:<owner>:<network>/<path>` (key), where a path
 * ending in exactly one `/` is a prefix. Returns null for anything else.
 */
export function parseEncryptionResource(
  uri: string,
): EncryptionResource | null {
  if (!uri.startsWith(ENCRYPTION_URN_PREFIX)) return null;
  const body = uri.slice(ENCRYPTION_URN_PREFIX.length);
  if (!body.includes("/")) {
    const bare = BARE_NETWORK_RE.exec(body);
    if (bare === null) return null;
    const [, ownerDid, network] = bare;
    if (ownerDid === undefined || network === undefined) return null;
    return { kind: "network", ownerDid, network };
  }
  const keyed = KEY_RE.exec(body);
  if (keyed === null) return null;
  const [, keyOwner, keyNetwork, keyPath] = keyed;
  if (keyOwner === undefined || keyNetwork === undefined) return null;
  if (keyPath === undefined || keyPath.length > MAX_KEY_PATH_BYTES) return null;
  return {
    kind: keyPath.endsWith("/") ? "prefix" : "key",
    ownerDid: keyOwner,
    network: keyNetwork,
    keyPath,
  };
}

/**
 * Whether a granted encryption resource covers a requested one. Exact covers
 * the same exact key; a prefix covers any key or prefix whose path starts
 * with the prefix path (its slash included); a network covers only the same
 * network. Owner and network must match exactly, and every other pairing is
 * false.
 */
export function encryptionResourceContains(
  granted: string,
  requested: string,
): boolean {
  const g = parseEncryptionResource(granted);
  const r = parseEncryptionResource(requested);
  if (g === null || r === null) return false;
  if (g.ownerDid !== r.ownerDid || g.network !== r.network) return false;
  if (g.kind === "network" || r.kind === "network") {
    return g.kind === "network" && r.kind === "network";
  }
  if (g.kind === "key") return r.kind === "key" && r.keyPath === g.keyPath;
  return r.keyPath.startsWith(g.keyPath);
}
