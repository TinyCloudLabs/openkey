// Refusal of encryption key grants under the `apps/` path prefix and of every
// `key.delete` grant. Checked at each place a sign-in message can reach a
// signer. The check does not depend on any flag.
//
// The ReCap blocks of a SIWE message are decoded here, strictly, so the answer
// does not depend on how the wasm parser presents a resource. A message whose
// ReCap cannot be read exactly is refused.

import { elevatedKindOf } from '@openkey/capability-review';
import { isAppsKeyResource, isEncryptionResource, isKeyDeleteAbility, keyPathOfAnyResource, parseKeyResource } from './key-resource';
import { decodeHexUtf8, isSiweShaped } from './siwe-origin';

export type AppKeyRefusalReason =
  | 'key_delete'
  /** An `apps/` grant with no admission: the site does not list it, or the request is not one a site can make. */
  | 'apps_key'
  | 'apps_key_unparsed'
  /** decrypt or key.create on an exact share key (`share/<id>`) that OpenKey did not make for the request (TC-2927). Same code as `apps_key`, its own words. */
  | 'share_key_not_minted'
  /** The request did not come from a verified https origin of the app's own site. */
  | 'apps_key_origin'
  /** The app id does not belong to the requesting site's host. */
  | 'apps_key_app_id'
  /** The site's manifest could not be fetched and matched, or has no usable app id. */
  | 'apps_key_manifest'
  /** The site's `keys` block cannot be read. */
  | 'apps_key_keys'
  /** The message does not say when access ends. */
  | 'apps_key_expiry'
  /** The owner or network is not the signer's own account. */
  | 'apps_key_account'
  | 'recap_unreadable';

export interface AppKeyRefusal {
  reason: AppKeyRefusalReason;
}

export type AppKeyRefusalCode = 'key_delete_not_grantable' | 'app_key_grant_refused' | 'invalid_siwe_recap';

/** Where the message came from: a website's own page, or something else (command line, device, link). */
export type AppKeyRequestSource = 'browser' | 'non_browser';

/** The parts of a wasm-parsed recap entry the second check reads. */
export interface RecapEntryLike {
  service?: string;
  space: string;
  path: string;
  actions: readonly string[];
}

const NOT_DECLARED_MESSAGE =
  "This website doesn't list the key this app asked for, so OpenKey didn't approve it.";
const SHARE_KEY_NOT_MINTED_MESSAGE = "This site isn't allowed to request that access.";
const ORIGIN_MESSAGE =
  "App keys can only be requested by the app's own website, so OpenKey didn't approve this request.";
const APP_ID_MESSAGE =
  "This app doesn't belong to this website, so OpenKey didn't approve its keys.";
const MANIFEST_MESSAGE =
  "OpenKey couldn't check this website's app details, so it didn't approve this request.";
const EXPIRY_MESSAGE = "This request doesn't say when access ends, so OpenKey didn't approve it.";
const ACCOUNT_MESSAGE = "This request doesn't match your account, so OpenKey didn't approve it.";
const KEYS_MESSAGE =
  "This website's list of app keys can't be read, so OpenKey didn't approve this request.";
const GROUP_PARTIAL_MESSAGE =
  "App keys can only be approved together, so OpenKey didn't approve this request.";
const KEY_DELETE_MESSAGE =
  "Apps can't be given permission to delete keys, so OpenKey didn't approve this request.";
const NON_BROWSER_MESSAGE =
  "App keys can only be requested through a website's sign-in, not from the command line or a device sign-in, so OpenKey didn't approve this request.";
// The wording the delegate routes already use for a recap they cannot read.
export const UNREADABLE_RECAP_MESSAGE = "This request's permission list can't be read, so OpenKey didn't approve it.";

const RECAP_RESOURCE = /urn:recap:(\S*)/gi;
const BASE64URL = /^[A-Za-z0-9_-]+={0,2}$/;

/**
 * Does this JSON text repeat a key inside any one object? `JSON.parse` keeps
 * the last value; a reader that keeps the first would see a different grant.
 * The text must already be valid JSON. Keys are compared after unescaping.
 */
function hasDuplicateJsonKeys(json: string): boolean {
  const objects: Array<Set<string> | null> = [];
  let expectKey = false;
  let i = 0;
  while (i < json.length) {
    const ch = json[i]!;
    if (ch === '"') {
      let end = i + 1;
      while (json[end] !== '"') end += json[end] === '\\' ? 2 : 1;
      const keys = objects[objects.length - 1];
      if (keys && expectKey) {
        const key = JSON.parse(json.slice(i, end + 1)) as string;
        if (keys.has(key)) return true;
        keys.add(key);
        expectKey = false;
      }
      i = end + 1;
      continue;
    }
    if (ch === '{') {
      objects.push(new Set());
      expectKey = true;
    } else if (ch === '[') {
      objects.push(null);
      expectKey = false;
    } else if (ch === '}' || ch === ']') {
      objects.pop();
      expectKey = false;
    } else if (ch === ',') {
      expectKey = objects[objects.length - 1] instanceof Set;
    }
    i += 1;
  }
  return false;
}

/**
 * The `att` block of one `urn:recap:` payload as `resource -> ability names`,
 * or `null` when the payload is not canonical base64url, not JSON, repeats a
 * key, or has no `att` object of ability objects.
 */
function recapAbilities(token: string): Record<string, string[]> | null {
  if (!BASE64URL.test(token)) return null;
  const unpadded = token.replace(/=+$/, '');
  const bytes = Buffer.from(unpadded, 'base64url');
  if (bytes.toString('base64url') !== unpadded) return null;
  const json = bytes.toString('utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
    if (hasDuplicateJsonKeys(json)) return null;
  } catch {
    return null;
  }
  const att = (parsed as { att?: unknown } | null)?.att;
  if (!att || typeof att !== 'object' || Array.isArray(att)) return null;
  const abilities: Record<string, string[]> = Object.create(null);
  for (const [resource, abilityMap] of Object.entries(att)) {
    if (!abilityMap || typeof abilityMap !== 'object' || Array.isArray(abilityMap)) return null;
    abilities[resource] = Object.keys(abilityMap);
  }
  return abilities;
}

/** An `apps/` resource admitted for one sign-in message, as written, with the abilities admitted on it. */
export interface AdmittedAppKey {
  resource: string;
  abilities: readonly string[];
}

function isAdmitted(
  resource: string,
  abilities: readonly string[],
  admitted: readonly AdmittedAppKey[] | undefined,
): boolean {
  const grant = admitted?.find((candidate) => candidate.resource === resource);
  return grant !== undefined && abilities.every((ability) => grant.abilities.includes(ability));
}

function refusalForResources(
  resources: Iterable<[string, readonly string[]]>,
  admitted?: readonly AdmittedAppKey[],
): AppKeyRefusal | null {
  let appsKey: AppKeyRefusalReason | null = null;
  for (const [resource, abilities] of resources) {
    if (abilities.some(isKeyDeleteAbility)) return { reason: 'key_delete' };
    if (isAppsKeyResource(resource) && !isAdmitted(resource, abilities, admitted)) {
      appsKey = parseKeyResource(resource) ? 'apps_key' : 'apps_key_unparsed';
    }
  }
  return appsKey ? { reason: appsKey } : null;
}

/** Every resource of every `urn:recap:` resource of a SIWE message with its ability names, or `null` when a ReCap cannot be read exactly. */
function recapResources(siwe: string): Array<[string, string[]]> | null {
  const resources: Array<[string, string[]]> = [];
  if (!isSiweShaped(siwe)) return resources;
  for (const match of siwe.matchAll(RECAP_RESOURCE)) {
    const abilities = recapAbilities(match[1]!);
    if (!abilities) return null;
    resources.push(...Object.entries(abilities));
  }
  return resources;
}

/** The `apps/` resources of a SIWE message with their abilities, as written. `null` when a ReCap cannot be read. */
export function appKeyResourcesOf(siwe: string): Array<[string, string[]]> | null {
  return recapResources(siwe)?.filter(([resource]) => isAppsKeyResource(resource)) ?? null;
}

/** `key.block` and `key.unblock` under any namespace, compared like `key.delete`. */
function isKeyBlockAbility(ability: string): boolean {
  const name = ability.slice(ability.lastIndexOf('/') + 1).toLowerCase();
  return name === 'key.block' || name === 'key.unblock';
}

/**
 * The encryption resources of a SIWE message outside `apps/` that carry
 * `key.block` or `key.unblock`: a bare network, a key or a prefix. The node
 * does not tie these two abilities to the requesting host, so a browser
 * request may name them only after the owner decided on the warning screen,
 * and a ticket request may not name them at all.
 */
export function blockResourcesOutsideApps(siwe: string): Array<[string, string[]]> {
  return (recapResources(siwe) ?? []).filter(
    ([resource, abilities]) =>
      isEncryptionResource(resource) &&
      !isAppsKeyResource(resource) &&
      abilities.some(isKeyBlockAbility),
  );
}

/** `decrypt` and `key.create` under any namespace, compared like `key.block`. */
function isEncryptionGrantAbility(ability: string): boolean {
  const name = ability.slice(ability.lastIndexOf('/') + 1).toLowerCase();
  return name === 'decrypt' || name === 'key.create';
}

/** An exact share key: `share/<id>`, one segment under `share/` (compared like the other key paths). */
const EXACT_SHARE_KEY = /^share\/[^/]+$/i;

/**
 * Refusal for a SIWE message whose ReCap asks to `decrypt` or `key.create` on an exact share key (`share/<id>`).
 * The id of a share is a value the requesting app chooses or guesses, which the owner cannot judge, so an exact
 * share-key grant is accepted only for an id OpenKey made for the request (TC-2927; for every app, first-party
 * included, and for every route that signs a message). Until the new-share approval mints ids, none is accepted. The
 * prefix `share/` and the whole network are not exact keys: they go through the per-permission warning.
 * A ReCap that cannot be read exactly is refused too, never passed. The prepared-handoff (command line) routes do
 * not call this.
 */
export function exactShareKeyRefusal(siwe: string): AppKeyRefusal | null {
  const resources = recapResources(siwe);
  if (resources === null) return { reason: 'recap_unreadable' };
  const exact = resources.some(([resource, abilities]) => {
    const path = keyPathOfAnyResource(resource);
    return path !== null && EXACT_SHARE_KEY.test(path) && abilities.some(isEncryptionGrantAbility);
  });
  return exact ? { reason: 'share_key_not_minted' } : null;
}

/** Same check for a message as the signer will cover it: as written, and as UTF-8 when it is `0x` hex. */
export function exactShareKeyRefusalForMessage(message: string): AppKeyRefusal | null {
  const direct = exactShareKeyRefusal(message);
  if (direct) return direct;
  const decoded = decodeHexUtf8(message);
  return decoded === null ? null : exactShareKeyRefusal(decoded);
}

/**
 * Does this message ask for anything the extra warning screen covers: `decrypt`, `key.create`, `key.block` or
 * `key.unblock` on a whole encryption network, or on a key or prefix outside `apps/` (`elevatedKindOf`, shared with
 * the screen)? Text and `0x` hex are both read. A ReCap that cannot be read is not elevated here: the refusal checks
 * report it.
 */
export function messageHasElevatedPermissions(message: string): boolean {
  const hasElevated = (siwe: string): boolean =>
    (recapResources(siwe) ?? []).some(([resource, abilities]) =>
      abilities.some((ability) => elevatedKindOf({ service: 'encryption', space: 'encryption', path: resource }, ability) !== null),
    );
  if (hasElevated(message)) return true;
  const decoded = decodeHexUtf8(message);
  return decoded !== null && hasElevated(decoded);
}

/**
 * Look for `apps/` key resources and `key.delete` abilities in every
 * `urn:recap:` resource of one SIWE message, and for a ReCap that cannot be
 * read. `key.delete` is reported ahead of an `apps/` resource. Text that is not
 * SIWE-shaped has no ReCap and passes.
 *
 * `entries` are the wasm-parsed entries of the same message, when the caller
 * has them: `space` and `path` of every entry, under any service name, get the
 * same check, and so does the resource string that `space`, `service` and
 * `path` make together (the space-path form of an encryption resource).
 *
 * `admitted` lists the `apps/` resources an earlier step admitted for this
 * message. A resource is passed only when it is byte-equal to an admitted one
 * and carries no ability the admission did not name.
 */
export function appKeyRefusalForSiwe(
  siwe: string,
  entries?: readonly RecapEntryLike[],
  admitted?: readonly AdmittedAppKey[],
): AppKeyRefusal | null {
  const resources = recapResources(siwe);
  if (resources === null) return { reason: 'recap_unreadable' };
  for (const entry of entries ?? []) {
    resources.push([entry.space, [...entry.actions]], [entry.path, [...entry.actions]]);
    // The same entry as the resource string the text scan reads, so a space-path
    // resource is classified identically from both views.
    if (entry.service !== undefined) resources.push([`${entry.space}/${entry.service}/${entry.path}`, [...entry.actions]]);
  }
  return refusalForResources(resources, admitted);
}

/** Same check for a message as the signer will cover it: as written, and as UTF-8 when it is `0x` hex. */
export function appKeyRefusalForMessage(message: string): AppKeyRefusal | null {
  const direct = appKeyRefusalForSiwe(message);
  if (direct) return direct;
  const decoded = decodeHexUtf8(message);
  return decoded === null ? null : appKeyRefusalForSiwe(decoded);
}

export function appKeyRefusalCode(refusal: AppKeyRefusal): AppKeyRefusalCode {
  if (refusal.reason === 'key_delete') return 'key_delete_not_grantable';
  return refusal.reason === 'recap_unreadable' ? 'invalid_siwe_recap' : 'app_key_grant_refused';
}

export function appKeyRefusalStatus(refusal: AppKeyRefusal): 400 | 403 {
  return refusal.reason === 'recap_unreadable' ? 400 : 403;
}

export function appKeyRefusalMessage(refusal: AppKeyRefusal, source: AppKeyRequestSource): string {
  if (refusal.reason === 'key_delete') return KEY_DELETE_MESSAGE;
  if (refusal.reason === 'recap_unreadable') return UNREADABLE_RECAP_MESSAGE;
  if (refusal.reason === 'share_key_not_minted') return SHARE_KEY_NOT_MINTED_MESSAGE;
  if (source === 'browser' && refusal.reason === 'apps_key_origin') return ORIGIN_MESSAGE;
  if (source === 'browser' && refusal.reason === 'apps_key_app_id') return APP_ID_MESSAGE;
  if (source === 'browser' && refusal.reason === 'apps_key_manifest') return MANIFEST_MESSAGE;
  if (source === 'browser' && refusal.reason === 'apps_key_keys') return KEYS_MESSAGE;
  if (source === 'browser' && refusal.reason === 'apps_key_expiry') return EXPIRY_MESSAGE;
  if (source === 'browser' && refusal.reason === 'apps_key_account') return ACCOUNT_MESSAGE;
  return source === 'non_browser' ? NON_BROWSER_MESSAGE : NOT_DECLARED_MESSAGE;
}

/** JSON body for a refusal: the same `error` and `code` pair the other delegate routes return. */
export function appKeyRefusalBody(
  refusal: AppKeyRefusal,
  source: AppKeyRequestSource,
): { error: string; code: AppKeyRefusalCode } {
  return { error: appKeyRefusalMessage(refusal, source), code: appKeyRefusalCode(refusal) };
}

/** What the 400 for a partial app-key selection says. */
export const APP_KEY_GROUP_PARTIAL_MESSAGE = GROUP_PARTIAL_MESSAGE;

/** Code of the refusal for a narrowed selection that keeps an `apps/` row and drops anything else. */
export const APP_KEY_GROUP_PARTIAL_CODE = 'app_key_group_partial';

/**
 * Selection rule for admitted `apps/` grants: the app-key rows are approved
 * together with the rest of the request or removed as a unit. `appKeyIds` are
 * the action ids of the admitted rows, `allowedIds` every action id of the
 * request, `selectedIds` the selection. Returns true when the selection keeps
 * an app-key row and drops any other action.
 */
export function appKeyGroupPartial(
  appKeyIds: ReadonlySet<string>,
  allowedIds: ReadonlySet<string>,
  selectedIds: ReadonlySet<string>,
): boolean {
  if (appKeyIds.size === 0) return false;
  const keepsAppKey = [...appKeyIds].some((id) => selectedIds.has(id));
  if (!keepsAppKey) return false;
  return [...allowedIds].some((id) => !selectedIds.has(id));
}

/**
 * The action ids of the admitted `apps/` rows of a request: every action of an
 * entry whose path is one of the admitted resources, byte for byte.
 */
export function admittedAppKeyActionIds<Entry extends { path: string; actions: readonly string[] }>(
  entries: readonly Entry[],
  admitted: readonly AdmittedAppKey[] | undefined,
  actionId: (entry: Entry, action: string) => string,
): Set<string> {
  const ids = new Set<string>();
  for (const entry of entries) {
    if (!admitted?.some((grant) => grant.resource === entry.path)) continue;
    for (const action of entry.actions) ids.add(actionId(entry, action));
  }
  return ids;
}
