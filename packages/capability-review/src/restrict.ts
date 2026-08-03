// Restriction helpers.
//
// Restriction is the operation of applying a user's selection to a baseline
// review model. It returns a NEW model in which:
//   - Actions the user unchecked are dropped.
//   - Actions marked required are always kept (even if the caller "unchecked"
//     them — the widget should never allow this, but restrict is fail-closed).
//   - Grants with zero selected actions are dropped entirely.
//   - Immutable SIWE fields are copied verbatim from the baseline.
//
// Restriction is a lossy narrow, never a broaden. It never widens a caveat
// or adds a resource — that is the job of the API preparation path.

import type {
  CapabilityGrant,
  CapabilityReviewModel,
} from "./model.js";

export interface RestrictInput {
  baseline: CapabilityReviewModel;
  selectedActionIds: Set<string>;
}

export function restrictModel(input: RestrictInput): CapabilityReviewModel {
  const { baseline, selectedActionIds } = input;

  if (baseline.protocol !== "tinycloud-siwe-recap") {
    // Non-editable requests are always their baseline.
    return baseline;
  }

  const restrictedPermissions: CapabilityGrant[] = [];
  for (const grant of baseline.permissions) {
    const actions = grant.actions
      .map((a) => ({
        ...a,
        // Required actions are always selected regardless of the user's
        // selectedActionIds.
        selected: a.required || selectedActionIds.has(a.id),
      }))
      .filter((a) => a.selected);
    if (actions.length === 0) continue;
    restrictedPermissions.push({ ...grant, actions });
  }

  return {
    ...baseline,
    permissions: restrictedPermissions,
  };
}

/**
 * Selected action IDs for a fully-approved (default consent) baseline.
 */
export function defaultSelection(baseline: CapabilityReviewModel): Set<string> {
  const set = new Set<string>();
  for (const grant of baseline.permissions) {
    for (const action of grant.actions) {
      if (action.selected) set.add(action.id);
    }
  }
  return set;
}
