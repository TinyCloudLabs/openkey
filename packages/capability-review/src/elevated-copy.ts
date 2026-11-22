// Wording of the extra warning screen (TC-2927), Monica's final copy. It sits beside `copy.ts`, not in it: these are
// sentences on a screen of their own, not permission descriptors, and `test/copy-one-line.test.ts` holds every string of
// `copy.ts` to one phone line. UI components still take every word of the screen from here.

import type { ElevatedKind } from "./elevated.js";
import type { AllSecretsReach } from "./secret-keys.js";

// The extra warning screen for permissions an app may ask for only with a per-permission decision: decrypt, key
// creation, or blocking and unblocking keys on the encryption network, or on keys outside the app's own. `site` is the
// browser-verified origin host (for an embedded sign-in, the page that embeds it), never a name the app supplies; null
// where nothing is verified (a link), which reads "This request".

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

// A heading asked as a question (the all-secrets card) reads as a statement after a label.
const QUESTION_MARK = /\?$/;

/** One row on the review after a rejection. */
export function elevatedNotApprovedRow(heading: string): string {
  return `Not approved: ${heading.replace(QUESTION_MARK, "")}`;
}

/** Polite announcements; never an alert. */
export function elevatedDecidedAnnouncement(heading: string, allowed: boolean, left: number): string {
  const verb = allowed ? "Allowed" : "Rejected";
  const what = heading.replace(QUESTION_MARK, "");
  return left === 0 ? `${verb}: ${what}. All decided.` : `${verb}: ${what}. ${left} left to decide.`;
}

export function elevatedRejectedCountAnnouncement(count: number): string {
  return count === 1 ? "1 permission not approved." : `${count} permissions not approved.`;
}

/** Where a key permission applies, in plain words: the folder's last name, never a name the app supplies. */
export function elevatedWhereText(lastSegment: string | null): string {
  return lastSegment === null ? "your encrypted data" : `a folder named ${lastSegment}`;
}

/**
 * The heading and sentence of one card. `where` is `elevatedWhereText(...)`. A grant that includes blocking or
 * unblocking gets the "Control access" card, which names every action the grant carries.
 */
export function elevatedCard(
  kind: ElevatedKind,
  abilities: { decrypt: boolean; create: boolean; block?: boolean; unblock?: boolean },
  site: string | null,
  where: string,
): { heading: string; body: string } {
  const who = elevatedSubject(site);
  if (abilities.block || abilities.unblock) return elevatedControlCard(kind, abilities, who, where);
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

/** Said on the all-secrets card when no site is verified. */
export const ALL_SECRETS_UNVERIFIED_CUE = "OpenKey can't confirm which site asked.";

/**
 * The all-secrets card (TC-3800, Monica's W3a-W3c): a request that can open every secret, by decrypt on the
 * `secrets/` prefix or on a whole encryption network. `site` is the verified site; with none the card names "this
 * app" and says so in `cue`. The "older encrypted data" sentence is said only when a whole-network decrypt is in the
 * same request: the `secrets/` prefix alone does not open data encrypted to the account key.
 */
export function allSecretsCard(
  reach: AllSecretsReach,
  site: string | null,
): { heading: string; body: string; cue: string | null } {
  const verified = site !== null && site.length > 0;
  const who = verified ? site : "this app";
  const cue = verified ? null : ALL_SECRETS_UNVERIFIED_CUE;
  if (reach.kind === "whole-account") {
    return {
      heading: `Let ${who} open all your encrypted data?`,
      body: "That covers every secret and everything else you've encrypted in TinyCloud. Allow this only for an app you trust.",
      cue,
    };
  }
  const trust = "Allow this only for your own tools on a device you trust.";
  return {
    heading: reach.kind === "read-and-add" ? `Let ${who} read and add all your secrets?` : `Let ${who} read all your secrets?`,
    body: reach.alsoWholeAccount ? `It can also open older encrypted data on your account. ${trust}` : trust,
    cue,
  };
}

/** Said on the card that includes blocking. A block does not take back a key already handed out, so it says "refused". */
export const ELEVATED_BLOCK_NOTE = "Until the key is unblocked, requests to unlock the items it protects are refused, including your own.";

/** "a", "a and b", "a, b and c": no serial comma. */
function joinActions(parts: string[]): string {
  return parts.length <= 1 ? parts.join("") : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

/**
 * The card for a grant that includes blocking or unblocking keys, whatever else it carries: "Control access to
 * encryption keys {scope}", then "{who} could {actions} {scope}, for as long as this approval lasts.", and the
 * refusal sentence when blocking is included.
 */
function elevatedControlCard(
  kind: ElevatedKind,
  abilities: { decrypt: boolean; create: boolean; block?: boolean; unblock?: boolean },
  who: string,
  where: string,
): { heading: string; body: string } {
  const scope = kind === "encryption-network" ? "anywhere in your account" : `in ${where}`;
  // Key actions share the noun, once: "create, block and unblock encryption keys". Unlocking is its own phrase, and
  // the two phrases are joined with "and": "unlock encrypted items and block and unblock encryption keys".
  const keyActions = [
    ...(abilities.create ? ["create"] : []),
    ...(abilities.block ? ["block"] : []),
    ...(abilities.unblock ? ["unblock"] : []),
  ];
  const actions = [
    ...(abilities.decrypt ? ["unlock encrypted items"] : []),
    ...(keyActions.length > 0 ? [`${joinActions(keyActions)} encryption keys`] : []),
  ].join(" and ");
  const sentence = `${who} could ${actions} ${scope}, ${LAST_FOR_AS_LONG}.`;
  return {
    heading: `Control access to encryption keys ${scope}`,
    body: abilities.block ? `${sentence} ${ELEVATED_BLOCK_NOTE}` : sentence,
  };
}
