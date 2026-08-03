// Metadata trust decisions.
//
// Metadata (a manifest, an app-supplied label, a display name) can enrich a
// review model — but it can NEVER lower a structural severity. This helper
// centralizes the monotonicity rule so no consumer accidentally applies an
// unverified label to a "sensitive" grant and downgrades it.
//
// Trust status rank (from most trusted to least):
//   verified > unsigned > stale > wrong-key > digest-mismatch
//
// Only "verified" is allowed to add supplementary UI hints. Everything else
// forces the widget to render structural labels only.

import type {
  CapabilityGrant,
  CapabilityReviewModel,
  MetadataTrust,
  MetadataTrustStatus,
  PermissionSeverity,
} from "./model.js";
import { maxSeverity } from "./classify.js";

export function isVerified(trust: MetadataTrust): boolean {
  return trust.status === "verified";
}

/**
 * Merge a manifest-supplied label into a review model, respecting monotonicity.
 * If `trust.status !== "verified"`, this is a no-op.
 */
export function applyMetadataLabels(
  model: CapabilityReviewModel,
  labels: Record<string, string>,
): CapabilityReviewModel {
  if (!isVerified(model.metadataTrust)) return model;
  const permissions = model.permissions.map((grant): CapabilityGrant => {
    const label = labels[grant.id];
    if (!label) return grant;
    return { ...grant, metadataLabel: label };
  });
  return { ...model, permissions };
}

/**
 * Raise the severity of specific grants because a verified manifest declared
 * them to be sensitive (`dataCategory: "health"` etc). Never lowers.
 */
export function raiseSeverityFromMetadata(
  model: CapabilityReviewModel,
  overrides: Record<string, PermissionSeverity>,
): CapabilityReviewModel {
  if (!isVerified(model.metadataTrust)) return model;
  const permissions = model.permissions.map((grant): CapabilityGrant => {
    const requested = overrides[grant.id];
    if (!requested) return grant;
    const severity = maxSeverity(grant.severity, requested);
    return { ...grant, severity };
  });
  return { ...model, permissions };
}

/**
 * Sanity check: a metadata trust decision cannot be "upgraded" once assigned.
 * The server hands the widget the strongest status it can prove; the widget
 * must not later claim a stronger one.
 */
export function assertMetadataTrustMonotonic(
  previous: MetadataTrustStatus,
  next: MetadataTrustStatus,
): void {
  // Ranks:
  //   0..2 = failure states (never upgradable to signed)
  //   3    = unsigned (no manifest supplied)
  //   4    = origin-bound (browser origin proven + well-known digest match,
  //          but no cryptographic manifest signature). Sits BETWEEN
  //          `unsigned` and `verified` per the merge-readiness contract.
  //   5    = verified (signed manifest, digest match, in-window)
  const rank: Record<MetadataTrustStatus, number> = {
    "digest-mismatch": 0,
    "wrong-key": 1,
    stale: 2,
    unsigned: 3,
    "origin-bound": 4,
    verified: 5,
  };
  if (rank[next] > rank[previous]) {
    throw new Error(
      `metadata trust may not be upgraded from ${previous} to ${next}`,
    );
  }
}
