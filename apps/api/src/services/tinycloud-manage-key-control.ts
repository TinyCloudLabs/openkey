import { createHash, randomUUID } from 'node:crypto';

export const TINYCLOUD_MANAGE_KEY_MODES = [
  'APP_MANAGED',
  'USER_CONTROLLED_SHARED',
  'USER_CONTROLLED_EXCLUSIVE',
] as const;

export type TinyCloudManageKeyMode = typeof TINYCLOUD_MANAGE_KEY_MODES[number];

export function isTinyCloudManageKeyMode(value: unknown): value is TinyCloudManageKeyMode {
  return typeof value === 'string' && (TINYCLOUD_MANAGE_KEY_MODES as readonly string[]).includes(value);
}

export function requestDigest(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

export function controlMutationError(value: unknown): string | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return 'Request body must be an object';
  const body = value as Record<string, unknown>;
  if (!isTinyCloudManageKeyMode(body.mode)) return 'mode must be a TinyCloud signing mode';
  if (!Number.isSafeInteger(body.expectedEpoch) || (body.expectedEpoch as number) < 0) return 'expectedEpoch must be a non-negative integer';
  if (body.confirmation !== 'TAKE CONTROL') return 'Please type "TAKE CONTROL" exactly to confirm';
  return null;
}

function isAllowedModeTransition(from: TinyCloudManageKeyMode, to: TinyCloudManageKeyMode): boolean {
  // Taking control is one-way.  Returning a controlled key to application
  // management would silently discard the user's custody decision.
  return (from === 'APP_MANAGED' && to !== 'APP_MANAGED')
    || (from === 'USER_CONTROLLED_SHARED' && to === 'USER_CONTROLLED_EXCLUSIVE')
    || (from === 'USER_CONTROLLED_EXCLUSIVE' && to === 'USER_CONTROLLED_SHARED');
}

export async function changeTinyCloudManageKeyMode(
  prisma: any,
  userId: string,
  input: { mode: TinyCloudManageKeyMode; expectedEpoch: number; request: unknown },
) {
  return prisma.$transaction(async (tx: any) => {
    await tx.$queryRawUnsafe('SELECT "id" FROM "user" WHERE "id" = $1 FOR UPDATE', userId);
    const current = await tx.user.findUnique({
      where: { id: userId },
      select: { tinyCloudManageKeyMode: true, tinyCloudManageKeyPolicyEpoch: true },
    });
    if (!current) return { kind: 'not_found' as const };
    const epoch = Number(current.tinyCloudManageKeyPolicyEpoch);
    const digest = requestDigest(input.request);
    if (epoch !== input.expectedEpoch) {
      const replay = await tx.tinyCloudManageKeyControlEvent.findFirst({
        where: { userId, action: 'MODE_CHANGED', requestDigest: digest },
        orderBy: { createdAt: 'desc' },
      });
      if (replay && replay.policyEpoch === current.tinyCloudManageKeyPolicyEpoch
        && current.tinyCloudManageKeyMode === input.mode) {
        return { kind: 'unchanged' as const, epoch, mode: input.mode };
      }
      return { kind: 'stale' as const, epoch };
    }
    if (current.tinyCloudManageKeyMode === input.mode) return { kind: 'unchanged' as const, epoch, mode: input.mode };
    if (!isAllowedModeTransition(current.tinyCloudManageKeyMode as TinyCloudManageKeyMode, input.mode)) {
      return { kind: 'invalid_transition' as const, epoch, mode: current.tinyCloudManageKeyMode };
    }

    const result = await tx.user.updateMany({
      where: { id: userId, tinyCloudManageKeyPolicyEpoch: current.tinyCloudManageKeyPolicyEpoch },
      data: {
        tinyCloudManageKeyMode: input.mode,
        tinyCloudManageKeyPolicyEpoch: { increment: 1 },
        // Preserve the legacy global switch as a derived compatibility value.
        tinyCloudManageKeyEnabled: input.mode !== 'USER_CONTROLLED_EXCLUSIVE',
      },
    });
    if (result.count !== 1) return { kind: 'stale' as const, epoch };
    const nextEpoch = epoch + 1;
    if (input.mode === 'USER_CONTROLLED_EXCLUSIVE') {
      await tx.tinyCloudManageKeyAppPreference.updateMany({
        where: { userId, status: 'ENABLED' },
        data: { enabled: false, status: 'DISABLED' },
      });
    }
    await tx.tinyCloudManageKeyControlEvent.create({
      data: {
        id: randomUUID(), userId, policyEpoch: BigInt(nextEpoch), action: 'MODE_CHANGED',
        mode: input.mode, requestDigest: digest,
      },
    });
    return { kind: 'changed' as const, epoch: nextEpoch, mode: input.mode };
  });
}

export async function changeTinyCloudManageKeyGrant(
  prisma: any,
  userId: string,
  clientId: string,
  input: { enabled: boolean; expectedEpoch: number; request: unknown },
) {
  return prisma.$transaction(async (tx: any) => {
    await tx.$queryRawUnsafe('SELECT "id" FROM "user" WHERE "id" = $1 FOR UPDATE', userId);
    const user = await tx.user.findUnique({
      where: { id: userId }, select: { tinyCloudManageKeyMode: true, tinyCloudManageKeyPolicyEpoch: true },
    });
    if (!user) return { kind: 'not_found' as const };
    const epoch = Number(user.tinyCloudManageKeyPolicyEpoch);
    const digest = requestDigest(input.request);
    if (epoch !== input.expectedEpoch) {
      const replay = await tx.tinyCloudManageKeyControlEvent.findFirst({
        where: { userId, clientId, action: 'GRANT_CHANGED', requestDigest: digest },
        orderBy: { createdAt: 'desc' },
      });
      if (replay && replay.policyEpoch === user.tinyCloudManageKeyPolicyEpoch) {
        const replayGrant = await tx.tinyCloudManageKeyAppPreference.findUnique({
          where: { userId_clientId: { userId, clientId } },
          select: { enabled: true, status: true },
        });
        if (replayGrant && replayGrant.enabled === input.enabled
          && replayGrant.status === (input.enabled ? 'ENABLED' : 'DISABLED')) {
          return { kind: 'unchanged' as const, epoch, grant: replayGrant };
        }
      }
      return { kind: 'stale' as const, epoch };
    }
    const consent = await tx.oauthConsent.findFirst({
      where: { userId, clientId, scopes: { has: 'tinycloud:manage-key' } }, select: { clientId: true },
    });
    if (!consent) return { kind: 'missing_consent' as const };
    const client = await tx.oauthClient.findUnique({ where: { clientId }, select: { name: true, uri: true } });
    const existing = await tx.tinyCloudManageKeyAppPreference.findUnique({
      where: { userId_clientId: { userId, clientId } },
      select: { enabled: true, status: true },
    });
    if (existing && existing.enabled === input.enabled
      && existing.status === (input.enabled ? 'ENABLED' : 'DISABLED')) {
      return { kind: 'unchanged' as const, epoch, grant: existing };
    }
    const grant = await tx.tinyCloudManageKeyAppPreference.upsert({
      where: { userId_clientId: { userId, clientId } },
      create: { userId, clientId, enabled: input.enabled, status: input.enabled ? 'ENABLED' : 'DISABLED', clientNameSnapshot: client?.name, clientUriSnapshot: client?.uri },
      update: { enabled: input.enabled, status: input.enabled ? 'ENABLED' : 'DISABLED' },
    });
    const nextEpoch = epoch + 1;
    const updated = await tx.user.updateMany({
      where: { id: userId, tinyCloudManageKeyPolicyEpoch: user.tinyCloudManageKeyPolicyEpoch },
      data: { tinyCloudManageKeyPolicyEpoch: { increment: 1 } },
    });
    if (updated.count !== 1) return { kind: 'stale' as const, epoch };
    await tx.tinyCloudManageKeyControlEvent.create({
      data: { id: randomUUID(), userId, policyEpoch: BigInt(nextEpoch), action: 'GRANT_CHANGED', mode: user.tinyCloudManageKeyMode, clientId, requestDigest: digest },
    });
    return { kind: 'changed' as const, epoch: nextEpoch, grant };
  });
}

// The policy is evaluated under the signing transaction. The callback is run
// before the transaction commits, so a control mutation cannot interleave
// between an ALLOW decision and signature production.
export async function withTinyCloudManageKeySigningPolicy<T>(
  prisma: any,
  input: { userId: string; clientId: string; request: unknown },
  onAllow: (tx: any) => Promise<T>,
): Promise<{
  allowed: true;
  value: T;
} | {
  allowed: false;
  reason: 'signing_disabled' | 'user_exclusive' | 'missing_consent' | 'grant_disabled';
}> {
  return prisma.$transaction(async (tx: any) => {
    await tx.$queryRawUnsafe('SELECT "id" FROM "user" WHERE "id" = $1 FOR UPDATE', input.userId);
    const user = await tx.user.findUnique({
      where: { id: input.userId }, select: { tinyCloudManageKeyEnabled: true, tinyCloudManageKeyMode: true, tinyCloudManageKeyPolicyEpoch: true },
    });
    const consent = await tx.oauthConsent.findFirst({
      where: { userId: input.userId, clientId: input.clientId, scopes: { has: 'tinycloud:manage-key' } }, select: { clientId: true },
    });
    const grant = await tx.tinyCloudManageKeyAppPreference.findUnique({
      where: { userId_clientId: { userId: input.userId, clientId: input.clientId } }, select: { enabled: true, status: true },
    });
    const activeConsent = !!consent;
    const appManaged = user?.tinyCloudManageKeyMode === 'APP_MANAGED';
    const explicitlyAllowed = grant?.enabled === true && grant.status === 'ENABLED';
    const explicitlyBlocked = grant?.enabled === false || grant?.status === 'DISABLED';
    // Consent is the application-owned approval boundary unless the user has
    // explicitly blocked that app. Once the account moves to shared user
    // control, only the durable per-client grant can authorize signing.
    // Exclusive always wins, including while a client is racing a user control
    // mutation.
    let denialReason: 'signing_disabled' | 'user_exclusive' | 'missing_consent' | 'grant_disabled' | undefined;
    if (!user) denialReason = 'signing_disabled';
    else if (user.tinyCloudManageKeyMode === 'USER_CONTROLLED_EXCLUSIVE') denialReason = 'user_exclusive';
    else if (!user.tinyCloudManageKeyEnabled) denialReason = 'signing_disabled';
    else if (!activeConsent) denialReason = 'missing_consent';
    else if (appManaged ? explicitlyBlocked : !explicitlyAllowed) denialReason = 'grant_disabled';
    const allowed = denialReason === undefined;
    const epoch = user?.tinyCloudManageKeyPolicyEpoch ?? BigInt(0);
    await tx.tinyCloudManageKeySigningDecision.create({
      data: { id: randomUUID(), userId: input.userId, clientId: input.clientId, policyEpoch: epoch, allowed, reason: denialReason ?? 'allowed', requestDigest: requestDigest(input.request) },
    });
    if (denialReason) return { allowed: false as const, reason: denialReason };
    return { allowed: true as const, value: await onAllow(tx) };
  }, { timeout: 10_000 });
}
