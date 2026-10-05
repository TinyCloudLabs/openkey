/**
 * A user's primary key is their canonical TinyCloud key: the one active
 * managed key flagged `isCanonicalTinyCloud` (a partial unique index allows
 * at most one per user). External wallets and archived keys are never
 * primary.
 */
export function isPrimaryKey(key: {
  keyType: string;
  isCanonicalTinyCloud: boolean;
  archivedAt: Date | null;
}): boolean {
  return key.keyType === 'MANAGED' && key.isCanonicalTinyCloud === true && key.archivedAt === null;
}
