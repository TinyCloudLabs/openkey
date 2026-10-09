// Relative TinyCloud resource paths accepted for delegated KV/SQL grants:
// no wildcards, no empty segments, and an optional trailing slash for a
// prefix grant. Shared by device authorization and native delegation.
export const TINYCLOUD_DELEGATED_PATH = /^[A-Za-z0-9._~@+=,:-]+(?:\/[A-Za-z0-9._~@+=,:-]+)*\/?$/;
export const TINYCLOUD_DELEGATED_PATH_MAX_LENGTH = 256;
// Path roots that hold secrets; delegated grants never address them.
export const TINYCLOUD_DENIED_PATH_ROOTS: Readonly<Record<string, true>> = { secrets: true, vault: true };

export function tinycloudPathSegments(path: string): string[] {
  return path.split('/').filter(Boolean);
}

export function hasDotSegment(path: string): boolean {
  return tinycloudPathSegments(path).some((segment) => segment === '.' || segment === '..');
}
