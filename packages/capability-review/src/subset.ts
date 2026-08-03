// Subset validation.
//
// An edited delegation is valid iff every (service, space, path, action) in
// the CANDIDATE model appears in the BASELINE model with an action that is
// no broader than the baseline's. In practice that means:
//   - No new (service, space, path) tuple.
//   - No new action for an existing tuple.
//   - No broadening of a caveat (if the baseline said `kv/get`, the candidate
//     cannot say `kv/put`; caveats are structural, not lexical).
//   - No altered required action (structurally required actions must stay).
//   - No altered immutable SIWE field (checked separately in restrict.ts).
//
// The check is directional: `assertBaselineSubset(baseline, candidate)`
// rejects anything the candidate added.

import type { CapabilityReviewModel } from "./model.js";

export interface SubsetViolation {
  code:
    | "added-service"
    | "added-space"
    | "added-path"
    | "added-action"
    | "broadened-caveat"
    | "removed-required"
    | "changed-immutable-field";
  message: string;
}

export interface SubsetCheckResult {
  ok: boolean;
  violations: SubsetViolation[];
}

/**
 * Assert that `candidate` is a subset of `baseline`. Returns violations
 * rather than throwing so the caller can render every issue at once.
 */
export function assertBaselineSubset(
  baseline: CapabilityReviewModel,
  candidate: CapabilityReviewModel,
): SubsetCheckResult {
  const violations: SubsetViolation[] = [];

  // Non-editable protocols must match byte-for-byte.
  if (baseline.protocol !== "tinycloud-siwe-recap") {
    if (candidate.rawMessage !== baseline.rawMessage) {
      violations.push({
        code: "changed-immutable-field",
        message: "Non-editable request cannot change the signed bytes.",
      });
    }
    return { ok: violations.length === 0, violations };
  }

  // Immutable SIWE fields must not change.
  if (baseline.immutable && candidate.immutable) {
    const b = baseline.immutable;
    const c = candidate.immutable;
    const keys = [
      "address",
      "chainId",
      "domain",
      "issuedAt",
      "expirationTime",
      "spaceId",
      "nonce",
    ] as const;
    for (const k of keys) {
      if (String(b[k]) !== String(c[k])) {
        violations.push({
          code: "changed-immutable-field",
          message: `Immutable SIWE field "${k}" changed from ${b[k] ?? "?"} to ${c[k] ?? "?"}.`,
        });
      }
    }
  } else if (baseline.immutable && !candidate.immutable) {
    violations.push({
      code: "changed-immutable-field",
      message: "Candidate dropped required SIWE header fields.",
    });
  }

  // Build a baseline map keyed by permission id.
  const baselineByPerm = new Map(
    baseline.permissions.map((p) => [p.id, p]),
  );

  for (const cand of candidate.permissions) {
    const base = baselineByPerm.get(cand.id);
    if (!base) {
      violations.push({
        code: "added-space",
        message: `Candidate added grant ${cand.service} on ${cand.space}/${cand.path} not present in baseline.`,
      });
      continue;
    }
    // Index baseline actions by ability so we can compare caveats too.
    const baseActionByAbility = new Map(base.actions.map((a) => [a.ability, a]));
    for (const action of cand.actions) {
      const baseAction = baseActionByAbility.get(action.ability);
      if (!baseAction) {
        violations.push({
          code: "added-action",
          message: `Candidate added action ${action.ability} on ${cand.service} ${cand.space} ${cand.path}.`,
        });
        continue;
      }
      // Caveat comparison: candidate MUST carry the SAME MULTISET of
      // caveats as the baseline. A candidate that drops caveats is
      // broader than the baseline; a candidate that adds caveats might
      // seem narrower, but the WASM emitter cannot round-trip added
      // caveats so we still fail closed. Order MUST NOT matter — two
      // structurally identical multisets with different ordering are
      // equivalent per the ReCap spec (caveats are a set of restrictions,
      // not a sequence). Prior implementation used ordered JSON.stringify
      // which spuriously rejected re-ordered baselines. See
      // `canonicalMultisetEqual` below for the deep-equality rules.
      const baseCaveats = baseAction.caveats ?? [];
      const candCaveats = action.caveats ?? [];
      if (!canonicalMultisetEqual(baseCaveats, candCaveats)) {
        violations.push({
          code: "broadened-caveat",
          message: `Candidate caveats for ${action.ability} on ${cand.service} ${cand.space} ${cand.path} differ from baseline (baseline=${JSON.stringify(baseCaveats)}, candidate=${JSON.stringify(candCaveats)}).`,
        });
      }
    }
  }

  // Required actions must remain.
  for (const base of baseline.permissions) {
    for (const action of base.actions) {
      if (!action.required) continue;
      const candPerm = candidate.permissions.find((p) => p.id === base.id);
      const stillPresent =
        candPerm &&
        candPerm.actions.some(
          (a) => a.ability === action.ability && a.selected,
        );
      if (!stillPresent) {
        violations.push({
          code: "removed-required",
          message: `Required action ${action.ability} on ${base.service} ${base.space} ${base.path} is missing from the candidate.`,
        });
      }
    }
  }

  return { ok: violations.length === 0, violations };
}

/**
 * Deep-equality comparison that ignores property ordering. Produces a
 * canonical JSON string for arbitrary JSON values by sorting object
 * keys recursively. Arrays remain order-sensitive because ReCap caveats
 * MAY encode ordered sequences internally; only the outer collection of
 * caveats is a multiset.
 */
function canonicalJsonKey(value: unknown): string {
  return JSON.stringify(value, function (this: unknown, key: string, val: unknown) {
    void key;
    if (val === null || typeof val !== "object" || Array.isArray(val)) return val;
    const record = val as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort();
    const sorted: Record<string, unknown> = {};
    for (const k of sortedKeys) sorted[k] = record[k];
    return sorted;
  });
}

/**
 * Multiset equality: two caveat arrays are equal iff they contain the
 * same canonicalized elements with the same counts. Sorting the
 * canonical keys and comparing element-wise is O(n log n) and handles
 * duplicates correctly (whereas Set equality would collapse them).
 *
 * Empty parent caveats and empty child caveats compare equal, matching
 * the ReCap semantic that "no caveats" means "unrestricted".
 */
export function canonicalMultisetEqual(
  a: readonly unknown[],
  b: readonly unknown[],
): boolean {
  if (a.length !== b.length) return false;
  const sa = a.map(canonicalJsonKey).sort();
  const sb = b.map(canonicalJsonKey).sort();
  for (let i = 0; i < sa.length; i += 1) {
    if (sa[i] !== sb[i]) return false;
  }
  return true;
}
