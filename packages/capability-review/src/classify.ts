// Deterministic capability classification.
//
// Rules (order matters):
//   1. KV/SQL entries touching a secrets space get secret-reach families
//      before ownership classification. Secret reach and cross-owner access
//      are independent risk axes; the display label preserves both facts.
//   2. KV/SQL entries touching a KNOWN application-data path prefix get
//      classified as own-app-data (severity: standard for read, attention for
//      mutation). This covers Listen, Chat, Feed, Cycle-health etc. so a
//      request targeting a real app's data no longer collapses to a generic
//      "bootstrap-kv" grant.
//   3. Same as (2) but when the space owner does NOT match the signer, the
//      family becomes cross-app-data (severity: attention). Cross-app grants
//      are the primary "the app is reading OTHER people's data" case.
//   4. KV entries with a secret path (vault/secrets or secrets prefixes) get
//      the secret-read/mutation family.
//   5. Otherwise, KV/SQL/capabilities stay as their bootstrap family — this
//      is the default for whole-space grants without a recognizable path.
//   6. Named secret services split into read vs mutation.
//   7. Encryption services split into key material vs decrypt.
//   8. Unknown services fall back to the "unknown" family and elevate
//      severity.
//
// The classifier NEVER lowers severity based on metadata. Metadata may enrich
// the display label (see metadata.ts) but cannot flip a "sensitive" grant to
// "standard".

import type {
  CapabilityFamily,
  PermissionSeverity,
} from "./model.js";
import { isSecretsSpace } from "./app-scope.js";

interface RecapEntryLike {
  service: string;
  space: string;
  path: string;
  actions: string[];
  /**
   * @deprecated Use `requesterAddress` when the classifier is asked to
   * determine cross-app ownership. Kept only as a fall-through hint when
   * verified requester metadata is unavailable. `signerAddress` is the
   * OpenKey session signer — an implementation detail, not the requesting
   * app's identity — and using it as the ownership axis mis-labels every
   * cross-app request that shares a signer with the space owner.
   */
  signerAddress?: string | null;
  /**
   * The requesting app's *verified* Ethereum address, lowercased. When
   * supplied AND `requesterVerified === true`, the classifier compares the
   * space owner (derived from `space`) against this identity so a grant
   * on the requester's own space stays own-app-data while a grant on
   * anyone else's space becomes cross-app-data.
   *
   * Callers MUST NOT pass unverified addresses here — that would let a
   * malicious app claim ownership of another user's space and downgrade
   * the severity. Fail-closed rule: when metadata is unverifiable, leave
   * `requesterAddress` unset; the classifier then treats every non-empty
   * space it can't attribute as cross-app-data.
   */
  requesterAddress?: string | null;
  /**
   * True only when `requesterAddress` was derived from a signed manifest
   * whose digest matched, whose signature verified, and whose freshness
   * is within the configured window. Any lower trust state MUST leave
   * this false (or omit it), in which case the classifier fails closed
   * on cross-app labelling.
   */
  requesterVerified?: boolean;
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

// The single read-shaped verb the capabilities service is expected to
// carry. Sol MAJOR-1 re-fix: `get`, `peek`, and `list` are NOT
// registered structural capability actions — only `capabilities/read`
// is. Any capabilities grant that carries a verb outside this set falls
// into the fail-closed `unknown` family (see BOOTSTRAP_CAPABILITIES_SERVICES
// branch below), which elevates severity via `classifySeverityFromActions`.
const CAPABILITY_READ_VERBS = new Set(["read"]);

// The verbs the secrets service is expected to carry. Any grant on
// `tinycloud.secrets` (or `secrets`) with a verb outside this union is
// classified as `secret-mutation` — the fail-closed side of the
// sensitive/standard split — so unknown verbs stay inside the
// secret-access count and are surfaced at elevated severity rather than
// silently defaulting to the standard read-shaped family.
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
interface AppFamilyMatch {
  displayLabel: (path: string) => string;
}

function matchKvAppFamily(path: string): AppFamilyMatch | null {
  // Any non-empty path that is not the whole space counts as a
  // path-scoped app-data grant. We do NOT special-case any product name.
  if (!path) return null;
  return { displayLabel: (p: string) => `App data — ${p}` };
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

function isWholeSecretsNamespace(space: string, path: string): boolean {
  const normalizedPath = path.replace(/^\/+|\/+$/g, "");
  if (normalizedPath === "secrets" || normalizedPath === "vault/secrets") {
    return true;
  }
  return (
    normalizedPath === "" &&
    (space === "secrets" || /:secrets(?:\/|$)/.test(space))
  );
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

function withCrossUserSignal(isCrossApp: boolean, label: string): string {
  return isCrossApp ? `Cross-user — ${label}` : label;
}

export function classifyRecapEntry(entry: RecapEntryLike): {
  family: CapabilityFamily;
  displayLabel: string;
} {
  const { service, space, path } = entry;
  // Sol MAJOR-7: with NO verified requester identity, we must NOT fall
  // back to the signer address as the ownership axis. Doing so would
  // classify every KV/SQL grant on the signer's own space as own-app-data
  // even when the requesting app is completely unrelated to the signer's
  // identity (a widget path where `requesterAddress: null` and
  // `requesterVerified: false` are always passed). The correct fail-
  // closed behaviour is: without a verified requester, treat any grant
  // on a real space as cross-app-data (attention severity).
  const requesterAddress =
    entry.requesterVerified && entry.requesterAddress
      ? entry.requesterAddress.toLowerCase()
      : null;
  // Retain `signerAddress` extraction so the deprecated field still
  // reads correctly for callers that will migrate to `requesterAddress`
  // in a future release. It is INTENTIONALLY NOT part of the ownership
  // axis computation below.
  void (entry.signerAddress ? entry.signerAddress.toLowerCase() : null);
  const ownershipAxis = requesterAddress; // NO signer fallback (Sol MAJOR-7).
  const spaceOwner = ownerFromSpace(space);
  // Fail-closed: if we have a spaceOwner but NO trusted ownership axis
  // to compare against, treat the request as cross-app (attention).
  // Otherwise compare against the verified requester.
  const isCrossApp =
    spaceOwner !== null &&
    (ownershipAxis === null || spaceOwner !== ownershipAxis);

  // KV entries with a secret path are classified as secret-read/mutation,
  // not generic bootstrap-kv. Real CLI secret requests use tinycloud.kv with
  // paths like "vault/secrets/DEPLOY_KEY" or "secrets/MY_SECRET".
  if (BOOTSTRAP_KV_SERVICES.has(service)) {
    const hasMutation = entry.actions.some((a) =>
      MUTATION_VERBS.has(verbOf(a)),
    );
    const hasUnknownVerb = entry.actions.some(
      (a) => !SECRETS_KNOWN_VERBS.has(verbOf(a)),
    );
    const isSecretsShapedSpace = isSecretsSpace(space);
    const isWholeSecretNamespace = isWholeSecretsNamespace(space, path);

    // A mutation or unknown action always wins over list/metadata. This is
    // deliberately before the namespace-read branch so mixed grants cannot
    // hide write or fail-closed authority behind a listing label.
    if (
      (isSecretsShapedSpace || isWholeSecretNamespace) &&
      (hasMutation || hasUnknownVerb)
    ) {
      return {
        family: "secret-mutation",
        displayLabel: withCrossUserSignal(
          isCrossApp,
          `Secrets namespace (mutate) — ${path || "(entire namespace)"}`,
        ),
      };
    }

    // An empty path on a secrets-shaped space is whole-namespace authority.
    // A read here reaches every secret value, so it is sensitive rather than
    // the attention-level severity used for one named secret.
    if (
      (isSecretsShapedSpace || isWholeSecretNamespace) &&
      entry.actions.length > 0 &&
      (isWholeSecretNamespace || isNamespaceListing(entry.actions))
    ) {
      return {
        family: "secret-namespace-list",
        displayLabel: withCrossUserSignal(
          isCrossApp,
          isSecretValueRead(entry.actions)
            ? "Secret data — (entire secrets namespace)"
            : "Secret names and metadata — (entire secrets namespace)",
        ),
      };
    }

    if (
      path &&
      (path.startsWith("vault/secrets/") ||
        path.startsWith("secrets/") ||
        path === "vault/secrets" ||
        path === "secrets")
    ) {
      const isMutation = hasMutation || hasUnknownVerb;
      const secretName = path
        .replace(/^vault\/secrets\/?/, "")
        .replace(/^secrets\/?/, "") || "(entire secrets namespace)";
      return {
        family: isMutation ? "secret-mutation" : "secret-read",
        displayLabel: withCrossUserSignal(
          isCrossApp,
          isMutation
            ? `Named secret (mutate) — ${secretName}`
            : `Named secret (read) — ${secretName}`,
        ),
      };
    }

    if (isSecretsShapedSpace) {
      return {
        family: "secret-read",
        displayLabel: withCrossUserSignal(
          isCrossApp,
          `Secret data — ${path || "(entire secrets namespace)"}`,
        ),
      };
    }
    // Cross-app KV grant: reading/writing another user's KV space is
    // architecturally significant — attention severity is baked in by
    // classifySeverityFromActions when the family is cross-app-data.
    if (isCrossApp) {
      // Structural label only — never claim an app identity here.
      return { family: "cross-app-data", displayLabel: "Cross-user KV data" };
    }
    // Own-space + recognized app path: label with the app family.
    const appMatch = matchKvAppFamily(path);
    if (appMatch) {
      return { family: "own-app-data", displayLabel: appMatch.displayLabel(path) };
    }
    return { family: "bootstrap-kv", displayLabel: "Key-value storage" };
  }
  if (BOOTSTRAP_SQL_SERVICES.has(service)) {
    if (isSecretsSpace(space)) {
      const hasMutation = entry.actions.some((a) => {
        const verb = verbOf(a);
        return MUTATION_VERBS.has(verb) || verb === "schema";
      });
      const hasUnknownVerb = entry.actions.some(
        (a) => !SQL_KNOWN_VERBS.has(verbOf(a)),
      );
      if (hasMutation || hasUnknownVerb) {
        return {
          family: "secret-mutation",
          displayLabel: withCrossUserSignal(
            isCrossApp,
            `Secrets data (mutate) — ${path || "(entire namespace)"}`,
          ),
        };
      }
      if (isWholeSecretsNamespace(space, path)) {
        return {
          family: "secret-namespace-list",
          displayLabel: withCrossUserSignal(
            isCrossApp,
            "Secret data — (entire secrets namespace)",
          ),
        };
      }
      return {
        family: "secret-read",
        displayLabel: withCrossUserSignal(
          isCrossApp,
          `Secrets data — ${path || "(entire namespace)"}`,
        ),
      };
    }
    // Cross-app / own-app logic for non-secrets SQL grants. This follows the
    // secrets branch so cross-owner secret reach cannot be downgraded to the
    // attention-level cross-app family.
    if (isCrossApp) {
      return {
        family: "cross-app-data",
        displayLabel: "Cross-user SQL data",
      };
    }
    return { family: "bootstrap-sql", displayLabel: "SQL database" };
  }
  if (BOOTSTRAP_CAPABILITIES_SERVICES.has(service)) {
    // Fail-closed: a capabilities grant with an unknown verb is not a
    // known "read your permissions" shape. Downgrading it to
    // `bootstrap-capabilities` would silently classify it as standard
    // severity via `classifySeverityFromActions`. Route unknown verbs
    // through the `unknown` family so severity is elevated (attention
    // for reads, sensitive for mutations/decrypts).
    const allRead = entry.actions.every((a) => CAPABILITY_READ_VERBS.has(verbOf(a)));
    if (!allRead) {
      return {
        family: "unknown",
        displayLabel: `Unknown capabilities action on ${space || "(no space)"}`,
      };
    }
    return {
      family: "bootstrap-capabilities",
      displayLabel: "Capability metadata",
    };
  }
  if (SECRETS_SERVICES.has(service)) {
    const isMutation = entry.actions.some((a) => MUTATION_VERBS.has(verbOf(a)));
    // Fail-closed: an unknown verb on the secrets service could easily be
    // a mutation we do not yet recognize. Do not classify it as the
    // attention-level `secret-read` family and hide it in the standard
    // read bucket — treat it as `secret-mutation` (sensitive) so the
    // user sees the elevated severity and the grant remains inside the
    // secret-reach count.
    const hasUnknownVerb = entry.actions.some((a) => !SECRETS_KNOWN_VERBS.has(verbOf(a)));
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
      displayLabel: `Named secret (read) — ${describeName(path)}`,
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
  scope?: { service: string; space: string; path: string },
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
      return scope &&
        (BOOTSTRAP_KV_SERVICES.has(scope.service) ||
          BOOTSTRAP_SQL_SERVICES.has(scope.service)) &&
        isSecretsSpace(scope.space) &&
        isWholeSecretsNamespace(scope.space, scope.path)
        ? "sensitive"
        : "attention";
    case "secret-namespace-list":
      return "sensitive";
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
