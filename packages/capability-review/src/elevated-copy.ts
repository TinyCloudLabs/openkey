// Wording of the extra warning screen (TC-2927), Monica's final copy. It sits beside `copy.ts`, not in it: these are
// sentences on a screen of their own, not permission descriptors, and `test/copy-one-line.test.ts` holds every string of
// `copy.ts` to one phone line. UI components still take every word of the screen from here.

import type { ElevatedKind } from "./elevated.js";

// The extra warning screen for permissions an app may ask for only with a per-permission decision: decrypt or key
// creation on the encryption network, or on keys outside the app's own. `site` is the browser-verified origin host (for
// an embedded sign-in, the page that embeds it), never a name the app supplies; null where nothing is verified (a link),
// which reads "This request".

const LAST_FOR_AS_LONG = "for as long as this approval lasts";

function elevatedSubject(site: string | null): string {
  return site === null || site.length === 0 ? "This request" : site;
}

export function elevatedTitle(site: string | null): string {
  return `${elevatedSubject(site)} is asking for more access`;
}

export const ELEVATED_SUB = "These permissions go further than the rest of the request. Decide on each one.";
export const ELEVATED_REJECT = "Reject this permission";
export const ELEVATED_ALLOW = "Allow this permission";
export const ELEVATED_CONTINUE = "Continue";
export const ELEVATED_CONTINUE_HINT = "Decide on each permission to continue.";
export const ELEVATED_CHANGE = "Change";
export const ELEVATED_REJECTED_STATUS = "You rejected this permission.";
export const ELEVATED_ALLOWED_STATUS = "You allowed this permission.";
export const ELEVATED_WHOLE_CANCEL = "Cancel the whole request";
export const ELEVATED_WHOLE_ALLOW = "Allow and approve";

export function elevatedRejectNote(site: string | null): string {
  const who = elevatedSubject(site);
  return `If you reject it, the rest of the request is still approved. ${who} may not work fully.`;
}

export function elevatedWholeNote(site: string | null): string {
  return `${elevatedSubject(site)} sent this as one request, so you can approve all of it or none of it.`;
}

/** One row on the review after a rejection. */
export function elevatedNotApprovedRow(heading: string): string {
  return `Not approved: ${heading}`;
}

/** Polite announcements; never an alert. */
export function elevatedDecidedAnnouncement(heading: string, allowed: boolean, left: number): string {
  const verb = allowed ? "Allowed" : "Rejected";
  return left === 0 ? `${verb}: ${heading}. All decided.` : `${verb}: ${heading}. ${left} left to decide.`;
}

export function elevatedRejectedCountAnnouncement(count: number): string {
  return count === 1 ? "1 permission not approved." : `${count} permissions not approved.`;
}

/** Where a key permission applies, in plain words: the folder's last name, never a name the app supplies. */
export function elevatedWhereText(lastSegment: string | null): string {
  return lastSegment === null ? "your encrypted data" : `a folder named ${lastSegment}`;
}

/** The heading and sentence of one card. `where` is `elevatedWhereText(...)`. */
export function elevatedCard(
  kind: ElevatedKind,
  abilities: { decrypt: boolean; create: boolean },
  site: string | null,
  where: string,
): { heading: string; body: string } {
  const who = elevatedSubject(site);
  if (kind === "encryption-network") {
    if (abilities.decrypt) {
      return {
        heading: "Unlock all your encrypted data",
        body: `${who} could unlock everything encrypted to your account, including your secrets and data other apps saved, ${LAST_FOR_AS_LONG}.`,
      };
    }
    return {
      heading: "Create encryption keys anywhere in your account",
      body: `${who} could create new encryption keys anywhere in your account, ${LAST_FOR_AS_LONG}.`,
    };
  }
  if (abilities.decrypt && abilities.create) {
    return {
      heading: `Unlock and create encrypted items in ${where}`,
      body: `${who} could unlock the encrypted items in ${where} and create new encryption keys there, ${LAST_FOR_AS_LONG}.`,
    };
  }
  if (abilities.create) {
    return {
      heading: `Create encryption keys in ${where}`,
      body: `${who} could create new encryption keys in ${where}, ${LAST_FOR_AS_LONG}.`,
    };
  }
  return {
    heading: `Unlock encrypted items in ${where}`,
    body: `${who} could unlock the encrypted items in ${where}, ${LAST_FOR_AS_LONG}.`,
  };
}
