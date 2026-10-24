// Refusal of encryption key grants under the `apps/` path prefix and of every
// `key.delete` grant. Checked at each place a sign-in message can reach a
// signer. The check does not depend on any flag.
//
// The ReCap blocks of a SIWE message are decoded here, strictly, so the answer
// does not depend on how the wasm parser presents a resource. A message whose
// ReCap cannot be read exactly is refused.

import { isAppsKeyResource, isKeyDeleteAbility, parseKeyResource } from './key-resource';
import { decodeHexUtf8, isSiweShaped } from './siwe-origin';

export type AppKeyRefusalReason = 'key_delete' | 'apps_key' | 'apps_key_unparsed' | 'recap_unreadable';

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
const KEY_DELETE_MESSAGE =
  "Apps can't be given permission to delete keys, so OpenKey didn't approve this request.";
const NON_BROWSER_MESSAGE =
  "App keys can only be requested through a website's sign-in, not from the command line or a device sign-in, so OpenKey didn't approve this request.";
// The wording the delegate routes already use for a recap they cannot read.
const UNREADABLE_RECAP_MESSAGE = 'Invalid SIWE recap';

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

function refusalForResources(resources: Iterable<[string, readonly string[]]>): AppKeyRefusal | null {
  let appsKey: AppKeyRefusalReason | null = null;
  for (const [resource, abilities] of resources) {
    if (abilities.some(isKeyDeleteAbility)) return { reason: 'key_delete' };
    if (isAppsKeyResource(resource)) appsKey = parseKeyResource(resource) ? 'apps_key' : 'apps_key_unparsed';
  }
  return appsKey ? { reason: appsKey } : null;
}

/**
 * Look for `apps/` key resources and `key.delete` abilities in every
 * `urn:recap:` resource of one SIWE message, and for a ReCap that cannot be
 * read. `key.delete` is reported ahead of an `apps/` resource. Text that is not
 * SIWE-shaped has no ReCap and passes.
 *
 * `entries` are the wasm-parsed entries of the same message, when the caller
 * has them: `space` and `path` of every entry, under any service name, get the
 * same check.
 */
export function appKeyRefusalForSiwe(siwe: string, entries?: readonly RecapEntryLike[]): AppKeyRefusal | null {
  const resources: Array<[string, readonly string[]]> = [];
  if (isSiweShaped(siwe)) {
    for (const match of siwe.matchAll(RECAP_RESOURCE)) {
      const abilities = recapAbilities(match[1]!);
      if (!abilities) return { reason: 'recap_unreadable' };
      resources.push(...Object.entries(abilities));
    }
  }
  for (const entry of entries ?? []) {
    resources.push([entry.space, entry.actions], [entry.path, entry.actions]);
  }
  return refusalForResources(resources);
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
  return source === 'non_browser' ? NON_BROWSER_MESSAGE : NOT_DECLARED_MESSAGE;
}

/** JSON body for a refusal: the same `error` and `code` pair the other delegate routes return. */
export function appKeyRefusalBody(
  refusal: AppKeyRefusal,
  source: AppKeyRequestSource,
): { error: string; code: AppKeyRefusalCode } {
  return { error: appKeyRefusalMessage(refusal, source), code: appKeyRefusalCode(refusal) };
}
