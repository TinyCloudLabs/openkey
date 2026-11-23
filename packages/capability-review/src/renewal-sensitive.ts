// TC-3821: which grants a renewal lease needs the owner's "Renew sensitive access?" confirm for. The API refuses the
// lease without it, and the approval screen asks for it; both call `renewalEntryVerdict`, so the screen can never ask
// about a different set of grants than the server later checks. This file has no imports beyond the encryption helpers.

import { elevatedAbilityVerb, encryptionResourceOfEntry, type ElevatedEntryLike } from "./elevated.js";
import { parseEncryptionResource } from "./encryption-resource.js";

/** The encryption key path under which secrets live. */
const SECRETS_KEY_PREFIX = "secrets/";

// App manifest key abilities, plus the key description and wildcard permissions handled by renewal confirmation.
const RENEWABLE_ENCRYPTION_VERBS: ReadonlySet<string> = new Set([
  "decrypt", "key.create", "key.block", "key.unblock", "key.describe", "*",
]);

/** A permission entry as the check reads it: the ReCap parser's form, or a review grant's service, space, path and abilities. */
export interface RenewalEntryLike extends ElevatedEntryLike {
  /** Full ability strings, e.g. `tinycloud.encryption/decrypt`. */
  actions: readonly string[];
}

/**
 * `confirm`: the lease needs the owner's confirm. `unreadable`: an invalid encryption resource.
 * `unknown-verb`: an encryption verb this lease cannot carry. `none`: no restriction.
 */
export type RenewalEntryVerdict = "none" | "confirm" | "unreadable" | "unknown-verb";

/**
 * Any encryption permission on a `secrets/` key or prefix (one secret, a scope, or every secret), or decrypt (or `*`)
 * on a whole encryption network, which opens every secret under it, needs the confirm.
 */
export function renewalEntryVerdict(entry: RenewalEntryLike): RenewalEntryVerdict {
  const resource = encryptionResourceOfEntry(entry);
  const encryptionActions = entry.actions.filter((action) => /^(tinycloud\.)?encryption\//i.test(action));
  const encryption = resource !== null || entry.service === "encryption" || entry.service === "tinycloud.encryption" ||
    encryptionActions.length > 0;
  if (!encryption) return "none";
  const parsed = resource === null ? null : parseEncryptionResource(resource);
  if (parsed === null) return "unreadable";
  if (encryptionActions.some((action) => !RENEWABLE_ENCRYPTION_VERBS.has(action.slice(action.indexOf("/") + 1)))) {
    return "unknown-verb";
  }
  if (parsed.kind === "network") {
    return entry.actions.some((action) => ["decrypt", "*"].includes(elevatedAbilityVerb(action))) ? "confirm" : "none";
  }
  return parsed.keyPath.startsWith(SECRETS_KEY_PREFIX) ? "confirm" : "none";
}
