/** Prisma driver adapters wrap PostgreSQL SQLSTATEs inside P2010. Shared by
 * consent and the later code exchange, renewal, and revocation routes. */
export function nativeDelegationSqlState(error: unknown): string | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const value = error as { code?: string; meta?: { code?: string; driverAdapterError?: { cause?: { code?: string } } }; cause?: { code?: string } };
  return value.code === 'P2010'
    ? value.meta?.driverAdapterError?.cause?.code ?? value.meta?.code
    : value.code ?? value.cause?.code;
}

export function isNativeDelegationLockTimeout(error: unknown): boolean {
  return ['40P01', '55P03'].includes(nativeDelegationSqlState(error) ?? '');
}

export function nativeDelegationLockResponse(error: unknown): Response | null {
  return isNativeDelegationLockTimeout(error)
    ? Response.json({ error: 'temporarily_unavailable' }, { status: 503, headers: { 'Retry-After': '2' } })
    : null;
}
