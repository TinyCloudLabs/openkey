import type { CapabilityReviewModel } from '@openkey/capability-review';

/** The `/api/delegate/prepare` permission option fields the mapping reads. */
export interface ServerPermissionOption {
  key: string;
  actions: ReadonlyArray<{ key: string; ability: string; required: boolean }>;
}

const RAW_ENCRYPTION_SERVICE = 'tinycloud.encryption';
const RAW_ENCRYPTION_SPACE = 'encryption';
const RAW_ENCRYPTION_PREFIX = 'urn:tinycloud:encryption:';

/**
 * The capability-review grant ID for a server permission key. Both are
 * NUL-separated `service\0space\0path` with a canonical service, except for a
 * raw (top-level) encryption network: the server reports it as space
 * `encryption` with the network URN as path, while capability-review keeps
 * the resource URN as the space and an empty path.
 */
export function reviewGrantId(serverKey: string): string {
  const [service, space, path] = serverKey.split('\0');
  return service === RAW_ENCRYPTION_SERVICE && space === RAW_ENCRYPTION_SPACE && path?.startsWith(RAW_ENCRYPTION_PREFIX)
    ? `${service}\0${path}\0`
    : serverKey;
}

/**
 * Translate a capability-review selection (Set of client-side action IDs)
 * into the server's actionKey strings.
 *
 * Sol MAJOR-5 fix: capability-review grant IDs and server permission keys
 * are BOTH NUL-separated (`service\0space\0path`). The previous code
 * stripped NULs to spaces before lookup, which caused every grant ID to
 * miss and the selection to collapse to required-only actions.
 *
 * Correlation is done over the CANONICAL server keys — a server permission
 * has already been canonicalized (`kv` → `tinycloud.kv`) and
 * capability-review derives the same canonical service from the
 * `tinycloud.kv/get` ability. So a direct id-to-id lookup is safe AND
 * preserves independent selection when two paths share an ability (e.g.
 * `chat` vs `feed` KV grants). Required actions always stay selected.
 */
export function reviewSelectionToActionKeys(
  model: CapabilityReviewModel,
  permissions: readonly ServerPermissionOption[],
  selection: ReadonlySet<string>,
): string[] {
  const selectedAbilitiesByGrantId = new Map<string, Set<string>>();
  for (const grant of model.permissions) {
    for (const action of grant.actions) {
      if (selection.has(action.id)) {
        let abilities = selectedAbilitiesByGrantId.get(grant.id);
        if (!abilities) {
          abilities = new Set();
          selectedAbilitiesByGrantId.set(grant.id, abilities);
        }
        abilities.add(action.ability);
      }
    }
  }

  const out: string[] = [];
  for (const permission of permissions) {
    const selectedAbilities = selectedAbilitiesByGrantId.get(reviewGrantId(permission.key));
    for (const action of permission.actions) {
      if (action.required || selectedAbilities?.has(action.ability)) {
        out.push(action.key);
      }
    }
  }
  return out;
}
