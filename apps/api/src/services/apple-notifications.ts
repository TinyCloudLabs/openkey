// Apple server-to-server notifications for Sign in with Apple (TC-1231; plan
// TC-1188 §6). Apple POSTs `{"payload": "<JWS>"}` to /api/webhooks/apple when a
// user stops using Apple with OpenKey, deletes their Apple Account, or turns
// Hide My Email forwarding off or on.
//
// A revocation keeps the OpenKey account, its keys and the Apple link (D5): it
// wipes the stored Apple tokens and ends every OpenKey session, native grant and
// OAuth token the user holds. Delegations already issued stay valid until their
// own signed expiry.

import { createRemoteJWKSet, errors as joseErrors, jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { Context } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { configuredSocialProviderIds } from '../social-providers';
import { log, logError } from '../log';

export const APPLE_NOTIFICATION_ISSUER = 'https://appleid.apple.com';
const APPLE_KEYS_URL = new URL('https://appleid.apple.com/auth/keys');
const MAX_AGE_MS = 24 * 60 * 60 * 1000;
const EVENT_TIME_WINDOW_MS = 24 * 60 * 60 * 1000;
const MAX_JTI_LENGTH = 256;
const MAX_TYPE_LENGTH = 64;
// Apple documents seconds; some deliveries have been reported in milliseconds.
const MILLISECONDS_THRESHOLD = 1e12;

export type AppleNotificationType = 'email-disabled' | 'email-enabled' | 'consent-revoked' | 'account-deleted';

export type AppleNotification = {
  jti: string;
  /** The event name as Apple sent it (recorded for audit). */
  rawType: string;
  /** Normalised type; the legacy `account-delete` reads as `account-deleted`. Null for a type OpenKey does not act on. */
  type: AppleNotificationType | null;
  sub: string;
  eventTimeMs: number;
};

export type AppleNotificationOutcome =
  | 'duplicate' | 'unknown_subject' | 'ignored_type' | 'stale_revocation' | 'revoked' | 'email_updated' | 'email_ignored';

type ProcessDatabase = Pick<PrismaClient, '$transaction'>;
type Transaction = Parameters<Parameters<PrismaClient['$transaction']>[0]>[0];

/** The primary App ID notifications are addressed to, or null while the endpoint is off. */
export function appleWebhookAudience(env: NodeJS.ProcessEnv = process.env): string | null {
  const audience = env.APPLE_WEBHOOK_AUDIENCE?.trim();
  if (!audience || !configuredSocialProviderIds(env).includes('apple')) return null;
  return audience;
}

/** Seconds below 1e12, otherwise milliseconds; always returns milliseconds, or null if unusable. */
export function appleEventTimeMs(value: unknown): number | null {
  const number = typeof value === 'number' ? value
    : typeof value === 'string' && /^\d{1,16}$/.test(value) ? Number(value) : Number.NaN;
  if (!Number.isSafeInteger(number) || number <= 0) return null;
  return number < MILLISECONDS_THRESHOLD ? number * 1000 : number;
}

function normaliseType(type: string): AppleNotificationType | null {
  if (type === 'account-delete') return 'account-deleted';
  if (type === 'email-disabled' || type === 'email-enabled' || type === 'consent-revoked' || type === 'account-deleted') return type;
  return null;
}

// What a forged, malformed, expired or misaddressed token throws. Anything else,
// including Apple's key set failing to load and a kid it does not (yet) list
// during jose's reload cooldown, is an outage: it is answered 503 so Apple
// retries, never 400, which could drop a genuine revocation.
const INVALID_TOKEN_ERRORS = [
  joseErrors.JWSSignatureVerificationFailed, joseErrors.JWSInvalid, joseErrors.JWTInvalid,
  joseErrors.JWTClaimValidationFailed, joseErrors.JWTExpired, joseErrors.JOSEAlgNotAllowed,
  joseErrors.JOSENotSupported, joseErrors.JWKSMultipleMatchingKeys,
];

/**
 * Verifies the signed payload and returns its event, or null for anything that
 * is not a valid Apple notification (answered 400). Any other failure, such as
 * Apple's key set being unavailable, is thrown so it is answered 503.
 */
export async function verifyAppleNotification(
  payload: unknown,
  options: { jwks: JWTVerifyGetKey; audience: string; now?: () => number },
): Promise<AppleNotification | null> {
  if (typeof payload !== 'string' || payload.length === 0 || payload.length > 16 * 1024) return null;
  let claims: Record<string, unknown>;
  try {
    ({ payload: claims } = await jwtVerify(payload, options.jwks, {
      algorithms: ['RS256'],
      issuer: APPLE_NOTIFICATION_ISSUER,
      audience: options.audience,
      maxTokenAge: MAX_AGE_MS / 1000,
      requiredClaims: ['iat', 'jti', 'events'],
      currentDate: new Date(options.now?.() ?? Date.now()),
    }));
  } catch (error) {
    if (INVALID_TOKEN_ERRORS.some((invalid) => error instanceof invalid)) return null;
    throw error;
  }
  const { jti, iat } = claims;
  if (typeof jti !== 'string' || !jti || jti.length > MAX_JTI_LENGTH || typeof iat !== 'number') return null;
  let events: unknown = claims.events;
  if (typeof events === 'string') {
    try { events = JSON.parse(events); } catch { return null; }
  }
  if (!events || typeof events !== 'object' || Array.isArray(events)) return null;
  const { type, sub, event_time: eventTime } = events as Record<string, unknown>;
  if (typeof type !== 'string' || !type || type.length > MAX_TYPE_LENGTH) return null;
  if (typeof sub !== 'string' || !sub.trim()) return null;
  const eventTimeMs = appleEventTimeMs(eventTime);
  if (eventTimeMs === null || Math.abs(eventTimeMs - iat * 1000) > EVENT_TIME_WINDOW_MS) return null;
  return { jti, rawType: type, type: normaliseType(type), sub, eventTimeMs };
}

type EmailState = { appleEmailEventAt: Date | null; appleEmailUndeliverable: boolean };

/**
 * Email events apply in Apple event time against the row's own watermark.
 * A later event wins; at an equal time `email-disabled` wins, whichever order
 * the two arrive in. Returns the new state, or null when the event changes nothing.
 */
export function appleEmailTransition(state: EmailState, disabled: boolean, eventTimeMs: number): EmailState | null {
  const watermark = state.appleEmailEventAt?.getTime();
  if (watermark === undefined || eventTimeMs > watermark) {
    return { appleEmailEventAt: new Date(eventTimeMs), appleEmailUndeliverable: disabled };
  }
  if (eventTimeMs === watermark && disabled && !state.appleEmailUndeliverable) {
    return { appleEmailEventAt: state.appleEmailEventAt, appleEmailUndeliverable: true };
  }
  return null;
}

/** A revocation older than the latest sign-in or link by this `sub` is a late echo and is ignored. */
export function isStaleAppleRevocation(appleRestoredAt: Date | null, eventTimeMs: number): boolean {
  return appleRestoredAt !== null && eventTimeMs < appleRestoredAt.getTime();
}

/**
 * Ends everything that lets the user act without signing in again: native
 * grants and their OAuth tokens, every other OAuth token, and every session.
 * The caller holds the user row FOR UPDATE, the first lock in the order shared
 * with native renewal and account deletion (renew-revoke.ts).
 */
export async function revokeUserAccess(tx: Transaction, userId: string, reason: string, now = new Date()): Promise<void> {
  await tx.$queryRaw`SELECT id FROM tinycloud_native_grant WHERE "userId" = ${userId} FOR UPDATE`;
  await tx.tinyCloudNativeGrant.updateMany({
    where: { userId, status: { not: 'REVOKED' } },
    data: { status: 'REVOKED', revokedAt: now, revokedReason: reason },
  });
  await tx.oauthAccessToken.deleteMany({ where: { userId } });
  await tx.oauthRefreshToken.deleteMany({ where: { userId } });
  await tx.session.deleteMany({ where: { userId } });
}

/**
 * Whether the user's email is an Apple relay address that Apple reported as
 * no longer forwarding (email-disabled, or the Apple Account was deleted).
 */
export async function appleRelayEmailUndeliverable(
  database: Pick<PrismaClient, 'account'>, userId: string, email: string,
): Promise<boolean> {
  if (!email.toLowerCase().endsWith('@privaterelay.appleid.com')) return false;
  return (await database.account.count({
    where: { userId, providerId: 'apple', appleEmailUndeliverable: true },
  })) > 0;
}

type LockedAccount = EmailState & { id: string; userId: string; appleRestoredAt: Date | null };

async function applyEvent(tx: Transaction, event: AppleNotification, now: Date): Promise<AppleNotificationOutcome> {
  const linked = await tx.account.findUnique({
    where: { providerId_accountId: { providerId: 'apple', accountId: event.sub } },
    select: { userId: true },
  });
  if (!linked) return 'unknown_subject';
  if (!event.type) return 'ignored_type';
  await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${linked.userId} FOR UPDATE`;
  // Sessions before the account row, the order unlink and step-up use (they
  // lock their session, then change the account), so neither can deadlock this.
  await tx.$queryRaw`SELECT id FROM "session" WHERE "userId" = ${linked.userId} ORDER BY id FOR UPDATE`;
  const [account] = await tx.$queryRaw<LockedAccount[]>`
    SELECT id, "userId", "appleRestoredAt", "appleEmailEventAt", "appleEmailUndeliverable"
    FROM account WHERE "providerId" = 'apple' AND "accountId" = ${event.sub} FOR UPDATE`;
  // Unlinked or moved while this request waited: the next delivery reads it afresh.
  if (!account || account.userId !== linked.userId) throw new Error('Apple account changed during notification');

  if (event.type === 'email-disabled' || event.type === 'email-enabled') {
    const next = appleEmailTransition(account, event.type === 'email-disabled', event.eventTimeMs);
    if (!next) return 'email_ignored';
    await tx.account.update({ where: { id: account.id }, data: next });
    return 'email_updated';
  }

  if (isStaleAppleRevocation(account.appleRestoredAt, event.eventTimeMs)) return 'stale_revocation';
  // Apple stops relay forwarding when the Apple Account is deleted.
  const email = event.type === 'account-deleted' ? appleEmailTransition(account, true, event.eventTimeMs) : null;
  await tx.account.update({
    where: { id: account.id },
    data: {
      accessToken: null, refreshToken: null, idToken: null,
      accessTokenExpiresAt: null, refreshTokenExpiresAt: null,
      revokedAt: now,
      ...(email ?? {}),
    },
  });
  await revokeUserAccess(tx, account.userId, event.type === 'account-deleted' ? 'apple_account_deleted' : 'apple_consent_revoked', now);
  return 'revoked';
}

/** Applies one verified notification exactly once; the `jti` row commits with its effects. */
export async function processAppleNotification(
  database: ProcessDatabase, event: AppleNotification, now = new Date(),
): Promise<AppleNotificationOutcome> {
  return database.$transaction(async (tx) => {
    await tx.$executeRaw`SET LOCAL lock_timeout = '5s'`;
    const recorded = await tx.appleNotification.createMany({
      data: [{ jti: event.jti, eventType: event.rawType, eventTime: new Date(event.eventTimeMs), outcome: 'pending' }],
      skipDuplicates: true,
    });
    if (recorded.count !== 1) return 'duplicate';
    const outcome = await applyEvent(tx, event, now);
    await tx.appleNotification.update({ where: { jti: event.jti }, data: { outcome } });
    return outcome;
  }, { timeout: 15_000 });
}

export type AppleWebhookOptions = {
  database: ProcessDatabase;
  /** Apple's signing keys; tests inject a local set. Defaults to Apple's cached remote set. */
  jwks?: JWTVerifyGetKey;
  env?: NodeJS.ProcessEnv;
  now?: () => number;
};

const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * POST /api/webhooks/apple, outside Better Auth's base path. Not found while
 * Apple sign-in is off or no primary App ID audience is configured.
 */
export function createAppleWebhookHandler(options: AppleWebhookOptions) {
  let jwks = options.jwks;
  return async (c: Context): Promise<Response> => {
    const audience = appleWebhookAudience(options.env ?? process.env);
    if (!audience) return c.json({ error: 'Not found' }, 404);
    jwks ??= createRemoteJWKSet(APPLE_KEYS_URL);
    const body: unknown = await c.req.json().catch(() => null);
    const payload = body && typeof body === 'object' && 'payload' in body ? body.payload : undefined;
    let event: AppleNotification | null;
    try {
      event = await verifyAppleNotification(payload, { jwks, audience, now: options.now });
    } catch (error) {
      logError('error', 'apple_notification_failed', error);
      return c.json({ error: 'temporarily_unavailable' }, 503, NO_STORE);
    }
    if (!event) {
      log('warn', 'apple_notification_rejected');
      return c.json({ error: 'invalid_notification' }, 400, NO_STORE);
    }
    try {
      await processAppleNotification(options.database, event);
    } catch (error) {
      // Nothing committed, including the jti: Apple's retry is processed afresh.
      logError('error', 'apple_notification_failed', error);
      return c.json({ error: 'temporarily_unavailable' }, 503, NO_STORE);
    }
    log('info', 'apple_notification_processed');
    return c.json({ status: 'ok' }, 200, NO_STORE);
  };
}
