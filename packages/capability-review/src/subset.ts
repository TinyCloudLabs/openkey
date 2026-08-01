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
      // Caveat comparison: candidate MUST carry the SAME caveats (order
      // and content) as the baseline. A candidate that drops caveats is
      // broader than the baseline; a candidate that adds caveats might
      // seem narrower, but the WASM emitter cannot round-trip added
      // caveats so we still fail closed. Deep equality via JSON.stringify
      // — caveats are arbitrary JSON per the ReCap spec.
      const baseCav = JSON.stringify(baseAction.caveats ?? []);
      const candCav = JSON.stringify(action.caveats ?? []);
      if (baseCav !== candCav) {
        violations.push({
          code: "broadened-caveat",
          message: `Candidate caveats for ${action.ability} on ${cand.service} ${cand.space} ${cand.path} differ from baseline (baseline=${baseCav}, candidate=${candCav}).`,
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
