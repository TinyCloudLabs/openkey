import type { CapabilityReviewModel } from '@openkey/capability-review';
import { reviewActionId, selectedServerActionIds } from './delegate-review-selection';
import { validatePreviewSelection } from './preview-review';

// The two translations every signing page (popup and embedded) makes between
// its review selection and the server's action ids. Both pages call these, so
// the spelling of a request and the reading of its preview stay in one place.

/** The ids to send to `/authorize-sign-preview` and `/authorize-sign` for the selected actions. */
export function requestedActionIds(model: CapabilityReviewModel | null, selection: ReadonlySet<string>): string[] {
  return model ? selectedServerActionIds(model, selection) : [];
}

/** The review selection a preview describes, after the preview has been checked against the request. */
export function selectionFromPreview(
  preview: Record<string, unknown>,
  requested: readonly string[],
): Set<string> {
  return new Set([...validatePreviewSelection(preview, requested)].map(reviewActionId));
}
