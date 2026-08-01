// Deterministic capability classification.
//
// Rules (order matters):
//   1. KV/SQL entries touching a KNOWN application-data path prefix get
//      classified as own-app-data (severity: standard for read, attention for
//      mutation). This covers Listen, Chat, Feed, Cycle-health etc. so a
//      request targeting a real app's data no longer collapses to a generic
//      "bootstrap-kv" grant.
//   2. Same as (1) but when the space owner does NOT match the signer, the
//      family becomes cross-app-data (severity: attention). Cross-app grants
//      are the primary "the app is reading OTHER people's data" case.
//   3. KV entries with a secret path (vault/secrets or secrets prefixes) get
//      the secret-read/mutation family.
//   4. Otherwise, KV/SQL/capabilities stay as their bootstrap family — this
//      is the default for whole-space grants without a recognizable path.
//   5. Named secret services split into read vs mutation.
//   6. Encryption services split into key material vs decrypt.
//   7. Unknown services fall back to the "unknown" family and elevate
//      severity.
//
// The classifier NEVER lowers severity based on metadata. Metadata may enrich
// the display label (see metadata.ts) but cannot flip a "sensitive" grant to
// "standard".

import type {
  CapabilityFamily,
  PermissionSeverity,
} from "./model.js";

interface RecapEntryLike {
  service: string;
  space: string;
  path: string;
  actions: string[];
  /**
   * The signer's own EIP-55 address, lowercased. When provided, the classifier
   * compares against the space owner (derived from `space`) so a KV grant on
   * a DIFFERENT user's space is labelled `cross-app-data` (attention) rather
   * than being lumped into `bootstrap-kv`.
   *
   * Optional: legacy callers that don't supply it keep the old classification.
   */
  signerAddress?: string | null;
}

const BOOTSTRAP_KV_SERVICES = new Set([
  "tinycloud.kv",
  "kv",
]);

const BOOTSTRAP_SQL_SERVICES = new Set([
  "tinycloud.sql",
  "sql",
]);

const BOOTSTRAP_CAPABILITIES_SERVICES = new Set([
  "tinycloud.capabilities",
  "capabilities",
]);

const SECRETS_SERVICES = new Set([
  "tinycloud.secrets",
  "secrets",
]);

const ENCRYPTION_SERVICES = new Set([
  "tinycloud.encryption",
  "encryption",
]);

const MUTATION_VERBS = new Set([
  "put",
  "post",
  "write",
  "delete",
  "del",
  "admin",
  "grant",
  "revoke",
  "update",
  "create",
]);

const DECRYPT_VERBS = new Set([
  "decrypt",
  "unwrap",
]);

function verbOf(action: string): string {
  if (action.includes("/")) return action.slice(action.indexOf("/") + 1);
  return action;
}

/**
 * Known real-world path prefixes for TinyCloud apps. Used to give the review
 * UI a specific label instead of the generic "Key-value storage" fallback,
 * and to establish own-app vs cross-app data classification for grants that
 * are clearly app-scoped rather than whole-space.
 */
interface AppFamilyMatch {
  displayLabel: (path: string) => string;
}

const KV_APP_FAMILIES: Array<{ match: (path: string) => boolean; label: (path: string) => string }> = [
  { match: (p) => p === "listen" || p.startsWith("listen/"), label: (p) => `Listen — ${p}` },
  { match: (p) => p === "chat" || p.startsWith("chat/"), label: (p) => `Chat — ${p}` },
  { match: (p) => p === "feed" || p.startsWith("feed/") || p.startsWith("inbox/"), label: (p) => `Feed — ${p}` },
  { match: (p) => p === "cycle" || p.startsWith("cycle/") || p.startsWith("cycle/health/"), label: (p) => `Cycle health — ${p}` },
  { match: (p) => p === "metadata" || p.startsWith("metadata/"), label: (p) => `App metadata — ${p}` },
  { match: (p) => p === "credentials" || p.startsWith("credentials/"), label: (p) => `Credentials — ${p}` },
];

function matchKvAppFamily(path: string): AppFamilyMatch | null {
  if (!path) return null;
  for (const family of KV_APP_FAMILIES) {
    if (family.match(path)) {
      return { displayLabel: family.label };
    }
  }
  return null;
}

/**
 * Extract the space owner (EIP-55 address) from a tinycloud:pkh URI, if
 * present. Returns a lowercased hex address without any preceding chain
 * information. Returns null for non-pkh URIs.
 */
function ownerFromSpace(space: string): string | null {
  if (!space) return null;
  const match = space.match(/^tinycloud:pkh:eip155:\d+:(0x[a-fA-F0-9]{40})(?::|\/|$)/);
  if (!match || !match[1]) return null;
  return match[1].toLowerCase();
}

export function classifyRecapEntry(entry: RecapEntryLike): {
  family: CapabilityFamily;
  displayLabel: string;
} {
  const { service, space, path } = entry;
  const signerAddress = entry.signerAddress ? entry.signerAddress.toLowerCase() : null;
  const spaceOwner = ownerFromSpace(space);
  const isCrossApp =
    signerAddress !== null && spaceOwner !== null && spaceOwner !== signerAddress;

  // KV entries with a secret path are classified as secret-read/mutation,
  // not generic bootstrap-kv. Real CLI secret requests use tinycloud.kv with
  // paths like "vault/secrets/DEPLOY_KEY" or "secrets/MY_SECRET".
  if (BOOTSTRAP_KV_SERVICES.has(service)) {
    if (
      path &&
      (path.startsWith("vault/secrets/") ||
        path.startsWith("secrets/") ||
        path === "vault/secrets" ||
        path === "secrets")
    ) {
      const isMutation = entry.actions.some((a) => MUTATION_VERBS.has(verbOf(a)));
      const secretName = path
        .replace(/^vault\/secrets\/?/, "")
        .replace(/^secrets\/?/, "") || "(entire secrets namespace)";
      return {
        family: isMutation ? "secret-mutation" : "secret-read",
        displayLabel: isMutation
          ? `Named secret (mutate) — ${secretName}`
          : `Named secret (read) — ${secretName}`,
      };
    }
    // Cross-app KV grant: reading/writing another user's KV space is
    // architecturally significant — attention severity is baked in by
    // classifySeverityFromActions when the family is cross-app-data.
    if (isCrossApp) {
      const appMatch = matchKvAppFamily(path);
      const label = appMatch
        ? `Cross-user ${appMatch.displayLabel(path)} — owner ${spaceOwner}`
        : `Cross-user KV data — owner ${spaceOwner} path=${path || "(whole space)"}`;
      return { family: "cross-app-data", displayLabel: label };
    }
    // Own-space + recognized app path: label with the app family.
    const appMatch = matchKvAppFamily(path);
    if (appMatch) {
      return { family: "own-app-data", displayLabel: appMatch.displayLabel(path) };
    }
    return { family: "bootstrap-kv", displayLabel: "Key-value storage" };
  }
  if (BOOTSTRAP_SQL_SERVICES.has(service)) {
    // Same cross-app / own-app logic for SQL grants — a SQL grant on
    // another user's space is cross-app-data.
    if (isCrossApp) {
      return {
        family: "cross-app-data",
        displayLabel: `Cross-user SQL data — owner ${spaceOwner} path=${path || "(whole space)"}`,
      };
    }
    return { family: "bootstrap-sql", displayLabel: "SQL database" };
  }
  if (BOOTSTRAP_CAPABILITIES_SERVICES.has(service)) {
    return {
      family: "bootstrap-capabilities",
      displayLabel: "Capability metadata",
    };
  }
  if (SECRETS_SERVICES.has(service)) {
    const isMutation = entry.actions.some((a) => MUTATION_VERBS.has(verbOf(a)));
    return {
      family: isMutation ? "secret-mutation" : "secret-read",
      displayLabel: isMutation
        ? `Named secret (mutate) — ${describeName(path)}`
        : `Named secret (read) — ${describeName(path)}`,
    };
  }
  if (ENCRYPTION_SERVICES.has(service)) {
    const hasDecrypt = entry.actions.some((a) => DECRYPT_VERBS.has(verbOf(a)));
    return {
      family: hasDecrypt ? "encryption-decrypt" : "encryption-key",
      displayLabel: hasDecrypt
        ? "Decrypt encrypted content"
        : "Encryption key material",
    };
  }

  // Unknown, own vs cross-app data.
  const spaceLabel = space && space.startsWith("tinycloud:") ? space.slice(space.lastIndexOf(":") + 1) : space;
  return {
    family: "unknown",
    displayLabel: `Unknown service ${service} on ${spaceLabel || "(no space)"}`,
  };
}

function describeName(path: string): string {
  if (!path) return "(entire secrets namespace)";
  return path;
}

/**
 * Structural severity — cannot be overridden by presentation metadata.
 * Severity ranking: "standard" < "attention" < "sensitive".
 */
export function classifySeverityFromActions(
  family: CapabilityFamily,
  actions: string[],
): PermissionSeverity {
  const verbs = actions.map(verbOf);
  const hasMutation = verbs.some((v) => MUTATION_VERBS.has(v));
  const hasDecrypt = verbs.some((v) => DECRYPT_VERBS.has(v));

  switch (family) {
    case "bootstrap-kv":
    case "bootstrap-sql":
      return hasMutation ? "attention" : "standard";
    case "bootstrap-capabilities":
      return "standard";
    case "own-app-data":
      return hasMutation ? "attention" : "standard";
    case "cross-app-data":
      return "attention";
    case "secret-read":
      return "attention";
    case "secret-mutation":
      return "sensitive";
    case "encryption-key":
      return "sensitive";
    case "encryption-decrypt":
      return hasDecrypt ? "sensitive" : "attention";
    case "unknown":
    default:
      // Fail-closed: an unknown service could be doing anything. Always
      // elevate at least to "attention"; if it also carries a mutation verb
      // the severity is "sensitive".
      return hasMutation || hasDecrypt ? "sensitive" : "attention";
  }
}

/**
 * Utility for callers that want to raise (never lower) severity.
 */
export function maxSeverity(
  a: PermissionSeverity,
  b: PermissionSeverity,
): PermissionSeverity {
  const rank: Record<PermissionSeverity, number> = {
    standard: 0,
    attention: 1,
    sensitive: 2,
  };
  return rank[a] >= rank[b] ? a : b;
}
