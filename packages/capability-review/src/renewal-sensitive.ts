// TC-3821: which grants a renewal lease needs the owner's "Renew sensitive access?" confirm for. The API refuses the
// lease without it, and the approval screen asks for it; both call `renewalEntryVerdict`, so the screen can never ask
// about a different set of grants than the server later checks. This file has no imports beyond the encryption helpers.

import { elevatedAbilityVerb, encryptionResourceOfEntry, type ElevatedEntryLike } from "./elevated.js";
import { parseEncryptionResource } from "./encryption-resource.js";

/** The encryption key path under which secrets live. */
const SECRETS_KEY_PREFIX = "secrets/";

/** A permission entry as the check reads it: the ReCap parser's form, or a review grant's service, space, path and abilities. */
export interface RenewalEntryLike extends ElevatedEntryLike {
  /** Full ability strings, e.g. `tinycloud.encryption/decrypt`. */
  actions: readonly string[];
}

/**
 * `confirm`: the lease needs the owner's confirm. `unreadable`: an encryption permission whose resource is not a valid
 * encryption URN, so the lease is refused outright. `none`: neither.
 */
export type RenewalEntryVerdict = "none" | "confirm" | "unreadable";

/**
 * Any encryption permission on a `secrets/` key or prefix (one secret, a scope, or every secret), or decrypt (or `*`)
 * on a whole encryption network, which opens every secret under it, needs the confirm. An encryption permission whose
 * resource does not parse is `unreadable`.
 */
export function renewalEntryVerdict(entry: RenewalEntryLike): RenewalEntryVerdict {
  const resource = encryptionResourceOfEntry(entry);
  const encryption = resource !== null || entry.service === "encryption" || entry.service === "tinycloud.encryption" ||
    entry.actions.some((action) => action.toLowerCase().startsWith("tinycloud.encryption/"));
  if (!encryption) return "none";
  const parsed = resource === null ? null : parseEncryptionResource(resource);
  if (parsed === null) return "unreadable";
  if (parsed.kind === "network") {
    return entry.actions.some((action) => ["decrypt", "*"].includes(elevatedAbilityVerb(action))) ? "confirm" : "none";
  }
  return parsed.keyPath.startsWith(SECRETS_KEY_PREFIX) ? "confirm" : "none";
}
