export interface TinyCloudManageKeyAppPreferencePatch {
  enabled: boolean;
}

export function parseTinyCloudManageKeyAppPreferencePatch(
  body: unknown,
): TinyCloudManageKeyAppPreferencePatch {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error('Request body must be an object');
  }
  const enabled = (body as Record<string, unknown>).enabled;
  if (typeof enabled !== 'boolean') {
    throw new Error('enabled must be a boolean');
  }
  return { enabled };
}
