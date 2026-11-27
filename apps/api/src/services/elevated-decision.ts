// The server half of the per-permission warning screen (TC-2927).
//
// An app may ask to `decrypt`, `key.create`, `key.block` or `key.unblock` on the encryption network, or on keys
// outside its own `apps/` area, but the owner decides on each such permission on an extra screen ("Reject this
// permission" / "Allow this permission"; the rest of the request is approved either way). The screen sends the
// action ids the owner allowed;
// the server recomputes which extra permissions the bytes to sign still carry (`elevatedActionsOf`, the same
// function the screen uses) and refuses to preview or sign unless every one was explicitly allowed. A permission the
// owner rejected is not in the narrowed bytes, so it needs nothing.
//
// This cannot prove a person tapped "Allow": it proves the request carries an explicit allow for exactly the
// permissions it is about to sign, so an out-of-date or modified client cannot sign one it never decided on.

import { elevatedActionsOf } from '@openkey/capability-review';
import { actionKey, type RecapEntry } from '../routes/delegate-session';

export const ELEVATED_NOT_DECIDED_CODE = 'elevated_not_decided';

/** The action ids a request says the owner allowed: `{ allowed: string[] }`. Anything else allows nothing. */
export function allowedElevatedIds(decision: unknown): Set<string> {
  if (typeof decision !== 'object' || decision === null || Array.isArray(decision)) return new Set();
  const allowed = (decision as { allowed?: unknown }).allowed;
  if (!Array.isArray(allowed)) return new Set();
  return new Set(allowed.filter((id): id is string => typeof id === 'string'));
}

/** Every extra permission the entries carry is among the allowed ids. */
export function elevatedDecided(entries: readonly RecapEntry[], allowed: ReadonlySet<string>): boolean {
  return elevatedActionsOf(entries, actionKey).every((action) => allowed.has(action.actionId));
}

export function elevatedNotDecidedBody(): { error: string; code: typeof ELEVATED_NOT_DECIDED_CODE } {
  return {
    error: "Each extra permission needs your decision first, so OpenKey didn't approve this request.",
    code: ELEVATED_NOT_DECIDED_CODE,
  };
}
