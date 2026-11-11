export function isEmptyLegacyDeclaration(item: { path: string; purpose: string; version: number; transform: string; expectedCount: number }): boolean {
  return item.path === 'openkey/user/{userId}/encryption'
    && item.purpose === 'legacy-user-encryption-empty' && item.version === 0
    && item.transform === 'sha256-getkey' && item.expectedCount === 0;
}
