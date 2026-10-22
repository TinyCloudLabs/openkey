// Copy projection.
//
// A shared string catalog so the CLI browser, popup, and iframe render the
// exact same words for the exact same review model. UI components MUST route
// their text through this file — never emit ad-hoc labels.

import type {
  CapabilityFamily,
  CapabilityGrant,
  PermissionSeverity,
  RequestProtocol,
} from "./model.js";

export const SEVERITY_HEADING: Record<PermissionSeverity, string> = {
  standard: "Standard permissions",
  attention: "Permissions that need attention",
  sensitive: "Sensitive permissions",
};

export const SEVERITY_HINT: Record<PermissionSeverity, string> = {
  standard: "Routine bootstrap access.",
  attention: "Grants access to app or user data.",
  sensitive: "Grants access to secrets or decrypted content.",
};

export const FAMILY_LABEL: Record<CapabilityFamily, string> = {
  "bootstrap-kv": "Key-value storage",
  "bootstrap-sql": "SQL database",
  "bootstrap-capabilities": "Capability metadata",
  "bootstrap-delegation": "Connected access and sharing",
  "own-app-data": "Application data",
  "cross-app-data": "Another user's data",
  "public-data": "Public data",
  "secret-read": "Named secret (read)",
  "secret-namespace-list": "Secret namespace access",
  "secret-mutation": "Named secret (mutate)",
  "encryption-key": "Encryption key material",
  "encryption-decrypt": "Decrypt encrypted content",
  "space-create": "Create a space",
  "space-read": "Space details",
  hooks: "Change notifications",
  "duckdb-data": "DuckDB database",
  "database-admin": "Database administration",
  "file-data": "Files",
  unknown: "Unknown capability",
};

/**
 * Consent copy for a raw `tinycloud.encryption/decrypt` on the account's
 * `:default` network. Single source of truth: statements.ts imports this
 * constant and tests compare against it.
 */
export const DECRYPT_DEFAULT_KEY_STATEMENT =
  "Decrypt anything encrypted with your account's default key — including your Secrets and every private share — whenever this app gets hold of the encrypted copy, until this access expires.";

/** Named-key verbs that carry consent copy. */
export type NamedKeyVerb = "create" | "decrypt" | "block" | "unblock" | "delete";

export const DELETE_REFUSED_TEMPLATE =
  "Delete the key {path}: only you can do this, with your wallet, as a separate step. This request is refused.";

/**
 * Named-key consent sentences, one per verb and resource shape. `{path}` is
 * the key path (a prefix keeps its trailing `/`) and `{network}` the network
 * name, both filled verbatim by renderNamedKeySentence. `null` means no
 * approved wording: the row renders the literal fallback instead.
 */
export const NAMED_KEY_STATEMENTS: Record<
  NamedKeyVerb,
  { key: string | null; prefix: string | null }
> = {
  create: {
    key: "Create the encryption key {path} in your account's {network} network.",
    prefix:
      "Create encryption keys under {path} in your account's {network} network.",
  },
  decrypt: {
    key: "Decrypt anything encrypted with your key {path} in your account's {network} network, whenever this app gets hold of the encrypted copy, until this access expires.",
    prefix:
      "Decrypt anything encrypted with any of your keys under {path} in your account's {network} network, whenever this app gets hold of the encrypted copy, until this access expires.",
  },
  block: {
    key: "Block the key {path} in your account's {network} network, so it can no longer decrypt. You can unblock it later.",
    prefix:
      "Block every key under {path} in your account's {network} network, so none of them can decrypt. You can unblock them later.",
  },
  unblock: {
    key: "Unblock the key {path} in your account's {network} network, so it can decrypt again.",
    prefix:
      "Unblock every key under {path} in your account's {network} network, so they can decrypt again.",
  },
  delete: {
    key: DELETE_REFUSED_TEMPLATE,
    prefix: DELETE_REFUSED_TEMPLATE,
  },
};

/**
 * Fill a named-key template. Split/join rather than String.replace so a `$`
 * in a network name is never read as a replacement pattern.
 */
export function renderNamedKeySentence(
  template: string,
  keyPath: string,
  network: string,
): string {
  return template
    .split("{path}")
    .join(keyPath)
    .split("{network}")
    .join(network);
}

export const PROTOCOL_HEADLINE: Record<RequestProtocol, string> = {
  "legacy-message": "Sign message",
  "siwe-plain": "Sign in with Ethereum",
  "tinycloud-siwe-recap": "Authorize capabilities",
  "malformed-recap": "Refusing to sign: malformed capability payload",
};

export const PROTOCOL_HINT: Record<RequestProtocol, string> = {
  "legacy-message":
    "You will sign these bytes exactly. Editing is not available.",
  "siwe-plain":
    "You will sign this SIWE message exactly. Editing is not available.",
  "tinycloud-siwe-recap":
    "Review the requested capabilities. Uncheck anything you do not want to grant.",
  "malformed-recap":
    "This message carries a capability payload we could not decode. Approving is disabled so a broken ReCap cannot be silently signed as an exact-byte SIWE.",
};

/**
 * Build the ordered rendering plan a UI needs: severity buckets, each with
 * a heading and the grants in stable order.
 */
export function buildRenderPlan(grants: CapabilityGrant[]): Array<{
  severity: PermissionSeverity;
  heading: string;
  hint: string;
  grants: CapabilityGrant[];
}> {
  const buckets: Record<PermissionSeverity, CapabilityGrant[]> = {
    sensitive: [],
    attention: [],
    standard: [],
  };
  for (const grant of grants) {
    buckets[grant.severity].push(grant);
  }
  // Stable order inside each bucket: family, then id.
  const ordered: PermissionSeverity[] = ["sensitive", "attention", "standard"];
  return ordered
    .filter((sev) => buckets[sev].length > 0)
    .map((sev) => ({
      severity: sev,
      heading: SEVERITY_HEADING[sev],
      hint: SEVERITY_HINT[sev],
      grants: [...buckets[sev]].sort((a, b) => {
        if (a.family !== b.family) return a.family.localeCompare(b.family);
        return a.id.localeCompare(b.id);
      }),
    }));
}

/**
 * Compact human label for a single grant. Prefers verified metadata label,
 * falls back to structural display label.
 */
export function grantHeading(grant: CapabilityGrant): string {
  return grant.metadataLabel ?? grant.displayLabel;
}
