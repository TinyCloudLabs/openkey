import type { PrismaClient } from '@openkey/db';

const CEREMONY_TTL_MS = 5 * 60 * 1000;
const MAX_PENDING_CEREMONIES = 10_000;

type CeremonyState = 'PENDING' | 'IN_FLIGHT' | 'RECORDING';
type Ceremony = { state: CeremonyState; expiresAt: number };
const ceremonies = new Map<string, Ceremony>();

function pruneCeremonies(now = Date.now()): void {
  for (const [id, ceremony] of ceremonies) {
    if (ceremony.expiresAt <= now) ceremonies.delete(id);
  }
}

/** Returns false instead of growing memory beyond the bounded marker store. */
export function issuePasskeyCeremony(ceremonyId: string, now = Date.now()): boolean {
  pruneCeremonies(now);
  if (ceremonies.size >= MAX_PENDING_CEREMONIES) return false;
  ceremonies.set(ceremonyId, { state: 'PENDING', expiresAt: now + CEREMONY_TTL_MS });
  return true;
}

/** Atomically reserves a marker for the verification currently in flight. */
export function beginPasskeyCeremony(ceremonyId: string, now = Date.now()): boolean {
  pruneCeremonies(now);
  const ceremony = ceremonies.get(ceremonyId);
  if (!ceremony || ceremony.state !== 'PENDING' || ceremony.expiresAt <= now) {
    ceremonies.delete(ceremonyId);
    return false;
  }
  ceremony.state = 'IN_FLIGHT';
  return true;
}

export function isPasskeyCeremonyInFlight(ceremonyId: string, now = Date.now()): boolean {
  pruneCeremonies(now);
  const ceremony = ceremonies.get(ceremonyId);
  return (ceremony?.state === 'IN_FLIGHT' || ceremony?.state === 'RECORDING') && ceremony.expiresAt > now;
}

/** Prevents two successful hook invocations from using one marker concurrently. */
function claimFreshnessRecording(ceremonyId: string, now: number): boolean {
  const ceremony = ceremonies.get(ceremonyId);
  if (!ceremony || ceremony.state !== 'IN_FLIGHT' || ceremony.expiresAt <= now) {
    ceremonies.delete(ceremonyId);
    return false;
  }
  ceremony.state = 'RECORDING';
  return true;
}

/** Consumes evidence only after the verified endpoint has returned success. */
export function completePasskeyCeremony(ceremonyId: string, now = Date.now()): boolean {
  pruneCeremonies(now);
  const ceremony = ceremonies.get(ceremonyId);
  if (!ceremony || ceremony.state !== 'RECORDING' || ceremony.expiresAt <= now) {
    ceremonies.delete(ceremonyId);
    return false;
  }
  ceremonies.delete(ceremonyId);
  return true;
}

/** Failed verification is discarded, so neither failure nor replay can bind freshness. */
export function discardPasskeyCeremony(ceremonyId: string): void {
  ceremonies.delete(ceremonyId);
}

export function pendingPasskeyCeremonyCount(now = Date.now()): number {
  pruneCeremonies(now);
  return ceremonies.size;
}

type SessionIssuedResponse = {
  session?: { id?: unknown; userId?: unknown };
};

function responseBody(value: unknown): Promise<SessionIssuedResponse | null> | SessionIssuedResponse | null {
  if (value instanceof Response) {
    if (value.status < 200 || value.status >= 300) return null;
    return value.clone().json().catch(() => null);
  }
  if (!value || typeof value !== 'object') return null;
  return value as SessionIssuedResponse;
}

/** The generic login path never records custody freshness without a marker. */
export function assertFreshPasskeyUserVerification(verification: {
  authenticationInfo?: { userVerified?: boolean };
}): void {
  if (verification.authenticationInfo?.userVerified !== true) {
    throw new Error('Custody freshness requires user verification');
  }
}

/**
 * Called from Better Auth's after hook after WebAuthn verification and session
 * creation. The marker must be an in-flight server-issued ceremony. The exact
 * server-issued session/user pair is the only row that can receive freshness.
 */
export async function recordVerifiedPasskeySession(
  db: Pick<PrismaClient, 'session'>,
  returned: unknown,
  ceremonyId: string | null | undefined,
  verifiedAt = new Date(),
): Promise<boolean> {
  if (!ceremonyId || !claimFreshnessRecording(ceremonyId, verifiedAt.getTime())) return false;
  const body = await responseBody(returned);
  const sessionId = body?.session?.id;
  const userId = body?.session?.userId;
  if (typeof sessionId !== 'string' || typeof userId !== 'string') {
    discardPasskeyCeremony(ceremonyId);
    return false;
  }

  let result: { count: number };
  try {
    result = await db.session.updateMany({
      where: { id: sessionId, userId, expiresAt: { gt: verifiedAt } },
      data: { lastPasskeyAt: verifiedAt },
    });
  } catch {
    discardPasskeyCeremony(ceremonyId);
    return false;
  }
  if (result.count !== 1) {
    discardPasskeyCeremony(ceremonyId);
    return false;
  }
  completePasskeyCeremony(ceremonyId, verifiedAt.getTime());
  return true;
}

/**
 * Adapts freshness recording to Better Auth's after-hook contract. Better Auth
 * 1.5.x reads properties from the hook result without guarding `undefined`, so
 * every matched hook must return an object even when no freshness marker exists.
 */
export async function recordPasskeyFreshnessAfterHook(
  db: Pick<PrismaClient, 'session'>,
  returned: unknown,
  ceremonyId: string | null | undefined,
): Promise<Record<string, never>> {
  await recordVerifiedPasskeySession(db, returned, ceremonyId);
  return {};
}
