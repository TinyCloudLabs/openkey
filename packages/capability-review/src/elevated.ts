// Which permissions an app may ask for only with an extra, per-permission warning (TC-2927).
//
// Sam's rule: an app may ask to use the encryption network, and other apps' data, but the approval shows an extra
// screen for those permissions with "Reject this permission", and the rest of the request is still approved. These
// are the permissions that screen covers:
//
//   - `decrypt`, `key.create`, `key.block` or `key.unblock` on a whole encryption network
//     (`urn:tinycloud:encryption:<owner>:<network>`), or on a key or prefix outside `apps/` (for example `share/`).
//     An app's own `apps/<id>/` keys go through the manifest admission instead and are not listed here.
//
// The web screen and the API guard both call `elevatedKindOf`, so the screen can never decide on a different set of
// permissions than the server later checks. This file has no imports beyond the key-resource helpers.

import {
  isAppsKeyResource,
  keyPathOfAnyResource,
  keyPathOfResource,
  KEY_RESOURCE_PREFIX,
  parseKeyResource,
} from "./key-resource.js";

/** A whole encryption network, or keys and prefixes outside `apps/`. */
export type ElevatedKind = "encryption-network" | "encryption-keys";

const ELEVATED_VERBS: ReadonlySet<string> = new Set(["decrypt", "key.create", "key.block", "key.unblock"]);
// The verbs an exact share key is refused for, whoever asks.
const SHARE_KEY_VERBS: ReadonlySet<string> = new Set(["decrypt", "key.create"]);

/** The part of a ReCap entry the check reads: the parser's form (`space: "encryption"`, `path: <urn>`) or the reported one. */
export interface ElevatedEntryLike {
  service?: string;
  space: string;
  path: string;
}

function isEncryptionService(service: string | undefined): boolean {
  return service === "encryption" || service === "tinycloud.encryption";
}

/** The encryption URN an entry names, whichever way the parser split it, or null when it names none. */
export function encryptionResourceOfEntry(entry: ElevatedEntryLike): string | null {
  const candidates = entry.path.length > 0 ? [entry.path, `${entry.space}/${entry.path}`] : [entry.space];
  return candidates.find((value) => value.slice(0, KEY_RESOURCE_PREFIX.length).toLowerCase() === KEY_RESOURCE_PREFIX) ?? null;
}

/** The verb of an ability (`tinycloud.encryption/decrypt` -> `decrypt`), lower-cased. */
export function elevatedAbilityVerb(ability: string): string {
  return ability.slice(ability.lastIndexOf("/") + 1).toLowerCase();
}

/**
 * `encryption-network` or `encryption-keys` when this entry's ability needs the extra warning, otherwise null.
 * `network.create` alone is not listed: every sign-in carries it and it reads nothing.
 */
export function elevatedKindOf(entry: ElevatedEntryLike, ability: string): ElevatedKind | null {
  if (!isEncryptionService(entry.service)) return null;
  if (!ELEVATED_VERBS.has(elevatedAbilityVerb(ability))) return null;
  const resource = encryptionResourceOfEntry(entry);
  if (resource === null || isAppsKeyResource(resource)) return null;
  return keyPathOfResource(resource) === null ? "encryption-network" : "encryption-keys";
}

/**
 * The text a card names where the permission applies: the last non-empty folder or key name, never a name the app
 * supplies. Null for a whole network.
 */
export function elevatedWhere(entry: ElevatedEntryLike): string | null {
  const resource = encryptionResourceOfEntry(entry);
  const path = resource === null ? null : keyPathOfResource(resource);
  if (path === null) return null;
  const segments = path.split("/").filter((segment) => segment.length > 0);
  return segments[segments.length - 1] ?? null;
}

/**
 * The name of the one key an entry grants, or null when it does not provably grant exactly one key. A key URN has no
 * trailing `/` and a prefix has exactly one, so `parseKeyResource` (which also checks the path grammar) tells them
 * apart: only `kind: "key"` counts. A prefix, a whole network, a path the grammar refuses and a URN written in another
 * letter case all give null. The name is the key's last segment, the same text `elevatedWhere` gives.
 */
export function elevatedExactKey(entry: ElevatedEntryLike): string | null {
  const resource = encryptionResourceOfEntry(entry);
  const parsed = resource === null ? null : parseKeyResource(resource);
  if (parsed === null || parsed.kind !== "key") return null;
  return parsed.keyPath.split("/").pop() ?? null;
}

/** An exact share key: `share/<id>`, one segment under `share/`. */
const EXACT_SHARE_KEY = /^share\/[^/]+$/i;

/**
 * Is this ability on this entry a `decrypt` or `key.create` on an exact share key (`share/<id>`)? The id of a share is
 * a value the app chooses or guesses, so an exact grant is accepted only for an id OpenKey made for the request
 * (TC-2927, for every app). The prefix `share/` and the whole network are not exact keys.
 */
export function isExactShareKeyGrant(entry: ElevatedEntryLike, ability: string): boolean {
  if (!isEncryptionService(entry.service?.toLowerCase())) return false;
  if (!SHARE_KEY_VERBS.has(elevatedAbilityVerb(ability))) return false;
  const resource = encryptionResourceOfEntry(entry) ?? (entry.path || entry.space);
  const path = keyPathOfAnyResource(resource)
    ?? keyPathOfAnyResource(`${entry.space}/${entry.service}/${entry.path}`);
  return path !== null && EXACT_SHARE_KEY.test(path);
}

/** One action of a request that needs the warning, in the ids the screen and the server both use. */
export interface ElevatedAction {
  actionId: string;
  kind: ElevatedKind;
  ability: string;
}

/**
 * The elevated actions among `entries`, in order. `actionId` builds the id exactly as the caller's request/response
 * protocol does (the server's `computeActionKey`, the screen's `actionId`).
 */
export function elevatedActionsOf<Entry extends ElevatedEntryLike & { actions: readonly string[] }>(
  entries: readonly Entry[],
  actionId: (entry: Entry, action: string) => string,
): ElevatedAction[] {
  const found: ElevatedAction[] = [];
  for (const entry of entries) {
    for (const action of entry.actions) {
      const kind = elevatedKindOf(entry, action);
      if (kind !== null) found.push({ actionId: actionId(entry, action), kind, ability: action });
    }
  }
  return found;
}
