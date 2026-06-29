export interface AutoSignPreferencePatch {
  autoSignEnabled: boolean;
}

export function parseAutoSignPreferencePatch(body: unknown): AutoSignPreferencePatch {
  if (!body || typeof body !== 'object') {
    throw new Error('Request body must be an object');
  }

  const value = (body as Record<string, unknown>).autoSignEnabled;
  if (typeof value !== 'boolean') {
    throw new Error('autoSignEnabled must be a boolean');
  }

  return { autoSignEnabled: value };
}
