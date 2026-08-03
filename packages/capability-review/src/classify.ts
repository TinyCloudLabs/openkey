// Deterministic capability classification.
//
// Rules (order matters):
//   1. Canonical TinyCloud spaces (`account`, `applications`, `public`,
//      `default`, `secrets`) and their registered actions map to their known
//      product meaning. Missing requester metadata never erases those facts.
//   2. Resource ownership is signer-relative. Only an owner that differs from
//      the signer is another-user access; app identity comes from a manifest,
//      not from an EVM resource owner.
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

import type { CapabilityFamily, PermissionSeverity } from "./model.js";
import { isSecretsSpace } from "./app-scope.js";
import { isMetadataOnlyAccess } from "./action-semantics.js";

interface RecapEntryLike {
  service: string;
  space: string;
  path: string;
  actions: string[];
  signerAddress?: string | null;
  /** Ability-derived and resource-derived services disagree on the wire. */
  serviceMismatch?: boolean;
}

const BOOTSTRAP_KV_SERVICES = new Set(["tinycloud.kv", "kv"]);

const BOOTSTRAP_SQL_SERVICES = new Set(["tinycloud.sql", "sql"]);

const BOOTSTRAP_CAPABILITIES_SERVICES = new Set([
  "tinycloud.capabilities",
  "capabilities",
]);

const DELEGATION_SERVICES = new Set(["tinycloud.delegation", "delegation"]);

const SECRETS_SERVICES = new Set(["tinycloud.secrets", "secrets"]);

const ENCRYPTION_SERVICES = new Set(["tinycloud.encryption", "encryption"]);

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

const DECRYPT_VERBS = new Set(["decrypt"]);

// The single read-shaped verb the capabilities service is expected to
// carry. Sol MAJOR-1 re-fix: `get`, `peek`, and `list` are NOT
// registered structural capability actions — only `capabilities/read`
// is. Any capabilities grant that carries a verb outside this set falls
// into the fail-closed `unknown` family (see BOOTSTRAP_CAPABILITIES_SERVICES
// branch below), which elevates severity via `classifySeverityFromActions`.
const CAPABILITY_READ_VERBS = new Set(["read"]);
const KV_VERBS = new Set(["get", "list", "metadata", "put", "del"]);
const ACCOUNT_REGISTRY_KV_VERBS = new Set(["get", "list", "put"]);
const ACCOUNT_SETUP_KV_VERBS = new Set(["get", "put"]);
const SQL_DATA_VERBS = new Set(["read", "write"]);
const SQL_DATABASE_VERBS = new Set(["read", "write", "schema"]);
const DELEGATION_VERBS = new Set(["list", "status"]);
const ENCRYPTION_NETWORK_VERBS = new Set(["network.create", "network.revoke"]);
const ENCRYPTION_VERBS = new Set([
  ...ENCRYPTION_NETWORK_VERBS,
  ...DECRYPT_VERBS,
]);

// The verbs the secrets service is expected to carry. Any grant on
// `tinycloud.secrets` (or `secrets`) with a verb outside this union is
// classified as `secret-mutation` so unknown verbs stay inside the
// secret-access count and are surfaced as sensitive rather than inheriting
// friendly read copy.
const SECRETS_KNOWN_READ_VERBS = new Set(["read", "get"]);
const SECRETS_KNOWN_VERBS = new Set([
  ...SECRETS_KNOWN_READ_VERBS,
  ...MUTATION_VERBS,
  "list",
  "metadata",
]);

const SQL_KNOWN_VERBS = new Set([
  "read",
  "select",
  "write",
  "schema",
  "admin",
]);

function verbOf(action: string): string {
  if (action.includes("/")) return action.slice(action.indexOf("/") + 1);
  return action;
}

/**
 * Structural label for a scoped app-data grant. Sol continuation contract:
 * we NEVER attach an application name (Listen, Chat, Feed, Cycle …) to a
 * capability grant based on a path prefix. That would let a malicious
 * origin request `listen/*` on the user's space and inherit trusted UI
 * labelling from a real product name. The label must remain STRUCTURAL —
 * derived from the literal path — unless verified presentation metadata
 * bound to the request supplies an app identity (see metadata.ts).
 *
 * We still detect that a path exists and is scoped to a sub-namespace so
 * classifyRecapEntry can flag it as own-app-data or cross-app-data (the
 * ownership distinction is a real structural fact about the space URI vs
 * the signer). But the DISPLAY label is always the literal path.
 */
function isScopedDataPath(path: string): boolean {
  // Any non-empty path that is not the whole space counts as a
  // path-scoped app-data grant. We do NOT special-case any product name.
  return path !== "" && path !== "/";
}

function isAccountApplicationsPath(path: string): boolean {
  return path === "applications" || path.startsWith("applications/");
}

function isAccountSpacesPath(path: string): boolean {
  return path === "spaces" || path.startsWith("spaces/");
}

/**
 * Extract the space owner (EIP-55 address) from a tinycloud:pkh URI, if
 * present. Returns a lowercased hex address without any preceding chain
 * information. Returns null for non-pkh URIs.
 */
function ownerFromSpace(space: string): string | null {
  if (!space) return null;
  const match = space.match(
    /^tinycloud:pkh:eip155:\d+:(0x[a-fA-F0-9]{40})(?::|\/|$)/,
  );
  if (!match || !match[1]) return null;
  return match[1].toLowerCase();
}

function spaceNameFromSpace(space: string): string | null {
  if (/^[a-z][a-z0-9-]*$/i.test(space)) return space.toLowerCase();
  const match = space.match(
    /^tinycloud:pkh:eip155:\d+:0x[a-fA-F0-9]{40}:([^/:]+)$/,
  );
  return match?.[1]?.toLowerCase() ?? null;
}

function allVerbsIn(actions: string[], allowed: ReadonlySet<string>): boolean {
  return (
    actions.length > 0 && actions.every((action) => allowed.has(verbOf(action)))
  );
}

function unknownActionLabel(service: string): {
  family: CapabilityFamily;
  displayLabel: string;
} {
  return {
    family: "unknown",
    displayLabel: `Unrecognized ${service} permission`,
  };
}

function isNamespaceListing(actions: string[]): boolean {
  return actions.some((action) => {
    const verb = verbOf(action);
    return verb === "list" || verb === "metadata";
  });
}

function isSecretValueRead(actions: string[]): boolean {
  return actions.some((action) => {
    const verb = verbOf(action);
    return verb === "get" || verb === "read" || verb === "select";
  });
}

export function classifyRecapEntry(entry: RecapEntryLike): {
  family: CapabilityFamily;
  displayLabel: string;
} {
  const { service, space, path } = entry;
  const signerAddress = entry.signerAddress?.toLowerCase() ?? null;
  const spaceOwner = ownerFromSpace(space);
  const spaceName = spaceNameFromSpace(space);
  const isOtherUser =
    spaceOwner !== null &&
    signerAddress !== null &&
    spaceOwner !== signerAddress;

  // KV and SQL authority inside a TinyCloud secrets space reaches secret
  // data regardless of requester ownership. Classify it as a secret family
  // before the generic cross-app branches so the default presentation is
  // sensitive. The origin-bound app-scope proof remains the sole place that
  // may later present an exact, manifest-declared KV secret as standard.
  if (
    isSecretsSpace(space) &&
    (BOOTSTRAP_KV_SERVICES.has(service) || BOOTSTRAP_SQL_SERVICES.has(service))
  ) {
    const knownActions = BOOTSTRAP_KV_SERVICES.has(service)
      ? allVerbsIn(entry.actions, KV_VERBS)
      : allVerbsIn(entry.actions, SQL_DATABASE_VERBS);
    const isMutation =
      !knownActions ||
      entry.actions.some((action) => {
        const verb = verbOf(action);
        return MUTATION_VERBS.has(verb) || verb === "schema";
      });
    const metadataOnly = isMetadataOnlyAccess(entry.actions);
    if (path === "" && !isMutation) {
      return {
        family: "secret-namespace-list",
        displayLabel: isSecretValueRead(entry.actions)
          ? "Secret data — (entire secrets namespace)"
          : "Secret names and metadata — (entire secrets namespace)",
      };
    }
    if (BOOTSTRAP_SQL_SERVICES.has(service)) {
      return {
        family: isMutation ? "secret-mutation" : "secret-read",
        displayLabel: `${isMutation ? "Secret catalog (manage)" : "Secret catalog (view)"} — ${describeName(path)}`,
      };
    }
    return {
      family: isMutation ? "secret-mutation" : "secret-read",
      displayLabel: `${
        isMutation
          ? "Secret values (update)"
          : metadataOnly
            ? "Secret names and metadata"
            : "Secret values (read)"
      } — ${describeName(path)}`,
    };
  }

  // KV entries with a secret path are classified as secret-read/mutation,
  // not generic bootstrap-kv. Real CLI secret requests use tinycloud.kv with
  // paths like "vault/secrets/DEPLOY_KEY" or "secrets/MY_SECRET".
  if (BOOTSTRAP_KV_SERVICES.has(service)) {
    if (!allVerbsIn(entry.actions, KV_VERBS)) {
      return unknownActionLabel(service);
    }
    if (
      path &&
      (path.startsWith("vault/secrets/") ||
        path.startsWith("secrets/") ||
        path === "vault/secrets" ||
        path === "secrets")
    ) {
      const isMutation = entry.actions.some((a) =>
        MUTATION_VERBS.has(verbOf(a)),
      );
      const secretName =
        path.replace(/^vault\/secrets\/?/, "").replace(/^secrets\/?/, "") ||
        "(entire secrets namespace)";
      const isWholeNamespace =
        path === "vault/secrets" || path === "secrets";
      return {
        family: isMutation
          ? "secret-mutation"
          : isWholeNamespace
            ? "secret-namespace-list"
            : "secret-read",
        displayLabel: isMutation
          ? `Named secret (mutate) — ${secretName}`
          : isWholeNamespace
            ? isSecretValueRead(entry.actions)
              ? "Secret data — (entire secrets namespace)"
              : "Secret names and metadata — (entire secrets namespace)"
            : `Named secret (read) — ${secretName}`,
      };
    }
    // Ability-derived and resource-derived services disagree. Outside the
    // structurally recognizable secret paths above, no friendly statement or
    // routine severity is safe for a malformed wire tuple.
    if (entry.serviceMismatch === true) {
      return unknownActionLabel(service);
    }
    let knownTarget: { family: CapabilityFamily; displayLabel: string };
    if (spaceName === "account") {
      if (isAccountApplicationsPath(path)) {
        if (!allVerbsIn(entry.actions, ACCOUNT_REGISTRY_KV_VERBS)) {
          return unknownActionLabel(service);
        }
        knownTarget = {
          family: "bootstrap-kv",
          displayLabel: "Connected app registry",
        };
      } else if (isAccountSpacesPath(path)) {
        if (!allVerbsIn(entry.actions, ACCOUNT_REGISTRY_KV_VERBS)) {
          return unknownActionLabel(service);
        }
        knownTarget = {
          family: "bootstrap-kv",
          displayLabel: "Storage space registry",
        };
      } else if (path === "system/bootstrap/complete") {
        if (!allVerbsIn(entry.actions, ACCOUNT_SETUP_KV_VERBS)) {
          return unknownActionLabel(service);
        }
        knownTarget = {
          family: "bootstrap-kv",
          displayLabel: "Account setup status",
        };
      } else {
        return { family: "unknown", displayLabel: "Unrecognized account data" };
      }
    } else if (spaceName === "applications") {
      knownTarget = { family: "own-app-data", displayLabel: "Application data" };
    } else if (spaceName === "public") {
      knownTarget = { family: "public-data", displayLabel: "Public data" };
    } else if (spaceName === "default") {
      knownTarget = isScopedDataPath(path)
        ? { family: "own-app-data", displayLabel: "Application data" }
        : { family: "bootstrap-kv", displayLabel: "TinyCloud data" };
    } else {
      return {
        family: "unknown",
        displayLabel: "Unrecognized key-value data",
      };
    }

    return isOtherUser
      ? { family: "cross-app-data", displayLabel: "Another user's data" }
      : knownTarget;
  }
  if (BOOTSTRAP_SQL_SERVICES.has(service)) {
    if (entry.serviceMismatch === true) {
      return unknownActionLabel(service);
    }
    let knownTarget: { family: CapabilityFamily; displayLabel: string };
    if (spaceName === "account" && path === "account") {
      if (!allVerbsIn(entry.actions, SQL_DATABASE_VERBS)) {
        return unknownActionLabel(service);
      }
      knownTarget = { family: "bootstrap-sql", displayLabel: "Account index" };
    } else if (spaceName === "applications" || spaceName === "default") {
      const scoped = isScopedDataPath(path);
      const allowed = scoped ? SQL_DATABASE_VERBS : SQL_DATA_VERBS;
      if (!allVerbsIn(entry.actions, allowed)) {
        return unknownActionLabel(service);
      }
      knownTarget = spaceName === "applications" || scoped
        ? { family: "own-app-data", displayLabel: "Application data" }
        : { family: "bootstrap-sql", displayLabel: "TinyCloud data" };
    } else if (spaceName === "public") {
      return {
        family: "unknown",
        displayLabel: "Unrecognized public data permission",
      };
    } else {
      return { family: "unknown", displayLabel: "Unrecognized SQL data" };
    }

    return isOtherUser
      ? { family: "cross-app-data", displayLabel: "Another user's data" }
      : knownTarget;
  }
  if (BOOTSTRAP_CAPABILITIES_SERVICES.has(service)) {
    if (entry.serviceMismatch === true) {
      return unknownActionLabel(service);
    }
    // Fail-closed: a capabilities grant with an unknown verb is not a
    // known "read your permissions" shape. Downgrading it to
    // `bootstrap-capabilities` would silently classify it as standard
    // severity via `classifySeverityFromActions`. Route unknown verbs
    // through the `unknown` family so severity is elevated (attention
    // for reads, sensitive for mutations/decrypts).
    const allRead = allVerbsIn(entry.actions, CAPABILITY_READ_VERBS);
    if (!allRead) {
      return {
        family: "unknown",
        displayLabel: `Unknown capabilities action on ${space || "(no space)"}`,
      };
    }
    if (isOtherUser) {
      return {
        family: "cross-app-data",
        displayLabel: "Another user's permission settings",
      };
    }
    return {
      family: "bootstrap-capabilities",
      displayLabel: `Permission check${spaceName ? ` — ${spaceName}` : ""}`,
    };
  }
  if (DELEGATION_SERVICES.has(service)) {
    if (entry.serviceMismatch === true) {
      return unknownActionLabel(service);
    }
    if (!allVerbsIn(entry.actions, DELEGATION_VERBS)) {
      return unknownActionLabel(service);
    }
    if (spaceName !== "account") {
      return {
        family: "unknown",
        displayLabel: "Unrecognized delegation target",
      };
    }
    if (isOtherUser) {
      return {
        family: "cross-app-data",
        displayLabel: "Another user's connected access",
      };
    }
    return {
      family: "bootstrap-delegation",
      displayLabel: "Connected access and sharing",
    };
  }
  if (SECRETS_SERVICES.has(service)) {
    if (entry.serviceMismatch === true) {
      return unknownActionLabel(service);
    }
    const isMutation = entry.actions.some((a) => MUTATION_VERBS.has(verbOf(a)));
    const metadataOnly = isMetadataOnlyAccess(entry.actions);
    // Fail-closed: an unknown verb on the secrets service could easily be
    // a mutation we do not yet recognize. Treat it as secret-mutation so
    // it stays Sensitive and inside the secret-reach count.
    const hasUnknownVerb = entry.actions.some(
      (a) => !SECRETS_KNOWN_VERBS.has(verbOf(a)),
    );
    if (isMutation || hasUnknownVerb) {
      return {
        family: "secret-mutation",
        displayLabel: `Named secret (mutate) — ${describeName(path)}`,
      };
    }
    if (path === "" && isNamespaceListing(entry.actions)) {
      return {
        family: "secret-namespace-list",
        displayLabel: isSecretValueRead(entry.actions)
          ? "Secret data — (entire secrets namespace)"
          : "Secret names and metadata — (entire secrets namespace)",
      };
    }
    return {
      family: "secret-read",
      displayLabel: `${
        metadataOnly ? "Secret names and metadata" : "Named secret (read)"
      } — ${describeName(path)}`,
    };
  }
  if (ENCRYPTION_SERVICES.has(service)) {
    if (entry.serviceMismatch === true) {
      return unknownActionLabel(service);
    }
    if (!allVerbsIn(entry.actions, ENCRYPTION_VERBS)) {
      return {
        family: "encryption-key",
        displayLabel: "Unrecognized encryption permission",
      };
    }
    const hasDecrypt = entry.actions.some((a) => DECRYPT_VERBS.has(verbOf(a)));
    return {
      family: hasDecrypt ? "encryption-decrypt" : "encryption-key",
      displayLabel: hasDecrypt
        ? "Decrypt encrypted content"
        : "Encryption key material",
    };
  }

  // Unknown, own vs cross-app data.
  const spaceLabel =
    space && space.startsWith("tinycloud:")
      ? space.slice(space.lastIndexOf(":") + 1)
      : space;
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
  scope?: { service: string; space: string; path: string },
): PermissionSeverity {
  const verbs = actions.map(verbOf);
  const hasMutation = verbs.some((v) => MUTATION_VERBS.has(v));
  const hasDecrypt = verbs.some((v) => DECRYPT_VERBS.has(v));

  switch (family) {
    case "bootstrap-kv":
    case "bootstrap-sql":
      return "standard";
    case "bootstrap-capabilities":
    case "bootstrap-delegation":
      return "standard";
    case "own-app-data":
      return "standard";
    case "cross-app-data":
      return "attention";
    case "public-data":
      return hasMutation ? "attention" : "standard";
    case "secret-read":
    case "secret-namespace-list":
      return "sensitive";
    case "secret-mutation":
      return "sensitive";
    case "encryption-key":
      return allVerbsIn(actions, ENCRYPTION_NETWORK_VERBS)
        ? "attention"
        : "sensitive";
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
