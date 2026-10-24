// Encryption key resources: `urn:tinycloud:encryption:<owner>:<network>/<path>`
// names one key; the same URN with one trailing `/` names every key under a
// path prefix.
//
// This file has no imports. The API image ships only `apps/api/src`, so the
// API keeps a byte-identical copy at `apps/api/src/services/key-resource.ts`
// (`__tests__/key-resource-parity.test.ts` compares the two).
//
// Paths are compared byte for byte. The trailing `/` of a prefix is part of
// the resource and is never trimmed or normalised.

export const KEY_RESOURCE_PREFIX = "urn:tinycloud:encryption:";
/** First path segment whose keys are granted per app. */
export const APPS_SEGMENT = "apps";

const SEGMENT = "[a-z0-9][a-z0-9._-]{0,63}";
const MAX_SEGMENTS = 8;
const MAX_PATH_LENGTH = 255;

const PATH = new RegExp(`^${SEGMENT}(?:/${SEGMENT}){0,${MAX_SEGMENTS - 1}}$`);
const APP_ID = new RegExp(`^${SEGMENT}$`);
// Owner DID and network name of a key resource. The path is validated
// separately so the rules for keys and prefixes stay in one place.
const KEY_RESOURCE = /^urn:tinycloud:encryption:(did:[a-z0-9]+:[A-Za-z0-9._:-]+):([A-Za-z0-9][A-Za-z0-9._-]{0,63})\/(.+)$/s;

export interface KeyResource {
  /** `prefix` when the URN ends in `/`. */
  kind: "key" | "prefix";
  owner: string;
  network: string;
  /** Path without the trailing `/` of a prefix. */
  keyPath: string;
  isPrefix: boolean;
}

/** App ids are used verbatim as one path segment: validated, never rewritten. */
export function appIdValid(id: string): boolean {
  return APP_ID.test(id);
}

// Under the `apps` segment a key has at least three segments
// (`apps/<id>/<name>`) and a prefix at least two (`apps/<id>/`).
function pathValid(path: string, minSegmentsUnderApps: number): boolean {
  if (path.length > MAX_PATH_LENGTH || !PATH.test(path)) return false;
  const segments = path.split("/");
  return segments[0] !== APPS_SEGMENT || segments.length >= minSegmentsUnderApps;
}

/** A key path: no trailing `/`. */
export function isKeyPath(path: string): boolean {
  return pathValid(path, 3);
}

/** A prefix path: exactly one trailing `/`, the rest valid. */
export function isPrefixPath(path: string): boolean {
  return path.endsWith("/") && pathValid(path.slice(0, -1), 2);
}

/**
 * Plain byte comparison on valid paths. A prefix ends in `/` and a key never
 * does, so a key that starts with the prefix is longer than it. A path the
 * grammar refuses is never covered.
 */
export function prefixCovers(prefix: string, key: string): boolean {
  return isPrefixPath(prefix) && isKeyPath(key) && key.startsWith(prefix);
}

/** Parse a key or prefix URN. Bare networks and anything invalid give `null`. */
export function parseKeyResource(uri: string): KeyResource | null {
  const isPrefix = uri.endsWith("/");
  const match = KEY_RESOURCE.exec(isPrefix ? uri.slice(0, -1) : uri);
  if (!match) return null;
  const [, owner, network, keyPath] = match as unknown as [string, string, string, string];
  if (isPrefix ? !isPrefixPath(`${keyPath}/`) : !isKeyPath(keyPath)) return null;
  return { kind: isPrefix ? "prefix" : "key", owner, network, keyPath, isPrefix };
}

/**
 * The text after the first `/` of anything that starts with the encryption
 * URN prefix (compared case-insensitively), or `null` when there is none.
 * No validation: callers use it to decide what a resource is shaped like.
 */
export function keyPathOfResource(uri: string): string | null {
  if (uri.slice(0, KEY_RESOURCE_PREFIX.length).toLowerCase() !== KEY_RESOURCE_PREFIX) return null;
  const slash = uri.indexOf("/", KEY_RESOURCE_PREFIX.length);
  return slash < 0 ? null : uri.slice(slash + 1);
}

// The space-path form of an encryption resource: a space resource whose service
// segment is `encryption` or `tinycloud.encryption`, in any space, then a path.
// `<space>/encryption` with no path names no key and does not match.
const SPACE_PATH_RESOURCE = /^tinycloud:[^/]*\/(?:tinycloud\.)?encryption\/(.*)$/is;

/**
 * The key path of a resource in either form: the text after the network of a
 * key URN (`keyPathOfResource`), or the path after the service segment of a
 * space resource. `null` when the resource has neither shape.
 */
export function keyPathOfAnyResource(uri: string): string | null {
  const match = SPACE_PATH_RESOURCE.exec(uri);
  return match ? match[1]! : keyPathOfResource(uri);
}

/**
 * Is this resource shaped like a key or prefix whose first segment is `apps`,
 * in either form? The comparison is case-insensitive.
 */
export function isAppsKeyResource(uri: string): boolean {
  const path = keyPathOfAnyResource(uri);
  if (path === null) return false;
  const slash = path.indexOf("/");
  return (slash < 0 ? path : path.slice(0, slash)).toLowerCase() === APPS_SEGMENT;
}
