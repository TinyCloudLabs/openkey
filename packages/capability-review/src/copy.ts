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
  "own-app-data": "Your app's data",
  "cross-app-data": "Cross-app data",
  "secret-read": "Named secret (read)",
  "secret-mutation": "Named secret (mutate)",
  "encryption-key": "Encryption key material",
  "encryption-decrypt": "Decrypt encrypted content",
  unknown: "Unknown capability",
};

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
