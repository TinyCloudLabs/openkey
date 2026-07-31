// Deterministic capability classification.
//
// Rules (order matters):
//   1. Known TinyCloud bootstrap services collapse to their bootstrap family.
//   2. Secret services split into read vs mutation.
//   3. Encryption services split into key material vs decrypt.
//   4. Own-space vs cross-space grants are labelled differently.
//   5. Unknown services fall back to the "unknown" family and elevate severity.
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

export function classifyRecapEntry(entry: RecapEntryLike): {
  family: CapabilityFamily;
  displayLabel: string;
} {
  const { service, space, path } = entry;

  if (BOOTSTRAP_KV_SERVICES.has(service)) {
    return { family: "bootstrap-kv", displayLabel: "Key-value storage" };
  }
  if (BOOTSTRAP_SQL_SERVICES.has(service)) {
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
