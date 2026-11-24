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
      const card = masterKeyDecryptCard(site, abilities.create);
      return { heading: card.heading, body: card.cue === null ? card.body : `${card.body} ${card.cue}` };
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

/** Said on every card that names the master key when no site is verified. The read cards without it keep the cue above. */
export const MASTER_KEY_UNVERIFIED_CUE = "OpenKey can't confirm the site.";

export const MASTER_KEY_TITLE = "Use your master key to decrypt?";
const MASTER_KEY_CREATE_LINE = "It can also create encryption keys.";

/**
 * The card for an app that asks to decrypt with the whole default network, that is, with the owner's master key. One
 * builder for both faces that ask it: `elevatedCard`'s whole-network decrypt and the all-secrets card's whole-account
 * kind. `site` is the verified site; with none the body says "This app" and `cue` says OpenKey can't confirm the site.
 * `withCreate` adds the key-creation line for a request that also creates keys on the whole network.
 */
function masterKeyDecryptCard(site: string | null, withCreate: boolean): { heading: string; body: string; cue: string | null } {
  const verified = site !== null && site.length > 0;
  const ask = `${verified ? site : "This app"} is asking to use your master key, which can open all your encrypted data. Some apps do this because they don't have app-specific keys.`;
  return {
    heading: MASTER_KEY_TITLE,
    body: withCreate ? `${ask} ${MASTER_KEY_CREATE_LINE}` : ask,
    cue: verified ? null : MASTER_KEY_UNVERIFIED_CUE,
  };
}

/**
 * The all-secrets card: a request that can open every secret, by decrypt on the
 * `secrets/` prefix or on a whole encryption network. `site` is the verified site; with none the card names "this
 * app" and says so in `cue`. A whole-network decrypt alone is the master-key card. Beside a `secrets/` read, the read
 * card names the master key in its title and body: the `secrets/` prefix alone does not open data encrypted to the
 * account key.
 */
export function allSecretsCard(
  reach: AllSecretsReach,
  site: string | null,
): { heading: string; body: string; cue: string | null } {
  if (reach.kind === "whole-account") return masterKeyDecryptCard(site, false);
  const verified = site !== null && site.length > 0;
  const who = verified ? site : "this app";
  const read = reach.kind === "read-and-add" ? "read and add all your secrets" : "read all your secrets";
  const trust = "Allow this only for your own tools on a device you trust.";
  if (reach.alsoWholeAccount) {
    return {
      heading: `Let ${who} ${read} and use your master key?`,
      body: `Your master key can open all your encrypted data. ${trust}`,
      cue: verified ? null : MASTER_KEY_UNVERIFIED_CUE,
    };
  }
  return {
    heading: `Let ${who} ${read}?`,
    body: trust,
    cue: verified ? null : ALL_SECRETS_UNVERIFIED_CUE,
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
