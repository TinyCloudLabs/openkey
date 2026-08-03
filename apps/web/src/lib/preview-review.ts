import { actionId } from '@openkey/capability-review';

interface PreviewPermission {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

function exactSetMatch(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  if (left.size !== right.size) return false;
  for (const value of left) {
    if (!right.has(value)) return false;
  }
  return true;
}

/**
 * Validate that the server preview describes the same selected actions the
 * user submitted and that its grouped permission projection agrees with its
 * canonical action IDs. The exact signed SIWE remains authoritative; this
 * check prevents the final human-readable review from drifting away from it.
 */
export function validatePreviewSelection(
  preview: Record<string, unknown>,
  requestedActionIds: readonly string[],
): Set<string> {
  if (
    !Array.isArray(preview.selectedActionKeys) ||
    !preview.selectedActionKeys.every((value): value is string => typeof value === 'string')
  ) {
    throw new Error('authorize-sign-preview did not return canonical selectedActionKeys');
  }
  if (!Array.isArray(preview.permissions)) {
    throw new Error('authorize-sign-preview did not return permissions');
  }

  const permissions: PreviewPermission[] = preview.permissions.map((permission) => {
    if (
      !permission ||
      typeof permission !== 'object' ||
      typeof (permission as any).service !== 'string' ||
      typeof (permission as any).space !== 'string' ||
      typeof (permission as any).path !== 'string' ||
      !Array.isArray((permission as any).actions) ||
      !(permission as any).actions.every((value: unknown) => typeof value === 'string')
    ) {
      throw new Error('authorize-sign-preview returned malformed permissions');
    }
    return permission as PreviewPermission;
  });

  const returned = new Set(preview.selectedActionKeys);
  const requested = new Set(requestedActionIds);
  if (!exactSetMatch(returned, requested)) {
    throw new Error('authorize-sign-preview selected actions differ from the reviewed selection');
  }

  const projected = new Set(
    permissions.flatMap((permission) =>
      permission.actions.map((ability) =>
        actionId(permission.service, permission.space, permission.path, ability),
      ),
    ),
  );
  if (!exactSetMatch(projected, returned)) {
    throw new Error('authorize-sign-preview permissions disagree with selectedActionKeys');
  }

  return returned;
}
