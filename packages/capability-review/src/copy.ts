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
  "app-keys": "App keys",
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

/** The abilities an app key grant can name, in the order their rows are shown. */
export const APP_KEY_ABILITIES = [
  "key.create",
  "decrypt",
  "key.block",
  "key.unblock",
  "key.delete",
] as const;

export type AppKeyAbility = (typeof APP_KEY_ABILITIES)[number];

/**
 * Consent copy for one ability on an app key (an exact key) or an app key
 * prefix. `path` is the key path, or the prefix with its trailing `/`; the
 * text between backticks is shown in monospace.
 */
export function appKeyStatementText(
  ability: AppKeyAbility,
  target: { path: string; isPrefix: boolean },
): string {
  const path = `\`${target.path}\``;
  switch (ability) {
    case "key.create":
      return target.isPrefix
        ? `Create new encryption keys under ${path}.`
        : `Create the encryption key ${path}.`;
    case "decrypt":
      return target.isPrefix
        ? `Decrypt data locked with any key under ${path}.`
        : `Decrypt data locked with the key ${path}.`;
    case "key.block":
      return target.isPrefix
        ? `Block any key under ${path} so it can't be used to decrypt.`
        : `Block the key ${path} so it can't be used to decrypt.`;
    case "key.unblock":
      return target.isPrefix
        ? `Unblock any key under ${path} so it can be used again.`
        : `Unblock the key ${path} so it can be used again.`;
    case "key.delete":
      return `Delete the key ${path}. Apps can't be given this permission.`;
  }
}

/** Shown while a request with app keys is being edited: the app keys are one unit. */
export const APP_KEY_GROUP_NOTE = "App keys can only be approved together. Untick all of them, or keep them all.";

export const APP_KEY_ACCESS_WITHOUT_EXPIRY = "This access lasts until it expires.";

/**
 * Standing-access line for app-key decrypt. `expiry` is the signed SIWE
 * `Expiration Time`. `formatExpiry` turns it into the text shown; without one
 * the signed value is shown as written.
 */
export function appKeyAccessStatement(
  expiry: string | null,
  formatExpiry: (expiry: string) => string = (value) => value,
): string {
  if (expiry === null || Number.isNaN(Date.parse(expiry))) return APP_KEY_ACCESS_WITHOUT_EXPIRY;
  return `This access lasts until ${formatExpiry(expiry)}.`;
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
