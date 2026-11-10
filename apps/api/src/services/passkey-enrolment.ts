import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthMiddleware } from 'better-auth/api';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import type { PrismaClient } from '@openkey/db';
import {
  consumeStepUpMarker,
  freshStepUpMarker,
  writeStepUpMarker,
  type PasskeyRegisterGrant,
} from './email-otp-step-up';
import { PASSKEY_STEP_UP_MAX_AGE_MS, freshStepUpPasskey } from './passkey-freshness';
import { appleRelayEmailUndeliverable } from './apple-notifications';
import { logError } from '../log';

// TC-1198 (plan TC-1188 §2, §3). Better Auth's passkey routes need only a
// session, so whoever holds one could enrol their own passkey, sign in with it
// and pass passkey step-up, or delete the owner's passkeys and fall back to a
// mailbox-only deletion. OpenKey gates enrolment and removal behind a fresh
// step-up and records, per credential, whether it counts for step-up.
//
// Rules:
// - Enrolment needs a fresh assertion by a passkey that counts, or a fresh
//   single-use email proof on this session: a `passkey_register` code, or the
//   session's own creation by a verified email code (sign-in or sign-up).
// - A passkey enrolled under a passkey assertion counts. One enrolled under an
//   email proof counts only while the user has no passkey that counts, so a
//   mailbox alone never adds step-up authority to a passkey user (D6).
// - Removing a passkey that counts needs a passkey assertion; removing one that
//   does not also accepts a single-use `passkey_remove` email code.
// - The typed 403 lists only methods that can work: no `email` while Apple
//   reports the user's relay address undeliverable, no `passkey` without one
//   that counts. An empty list means neither is available right now.

export type PasskeyStepUpMethod = 'passkey' | 'email';
export type PasskeyEnrolmentVia = PasskeyRegisterGrant | 'passkey_step_up';
export const PASSKEY_STEP_UP_REQUIRED = 'PASSKEY_STEP_UP_REQUIRED';

export type ResolvedSession = { session: { id: string; createdAt: Date }; user: { id: string; email: string } };
type SessionResolver = (headers: Headers) => Promise<ResolvedSession | null>;
type Database = Pick<PrismaClient, 'passkey' | 'session' | 'verification' | 'account' | '$transaction'>;

const REGISTER_GRANTS: Readonly<Record<string, true>> = { email_step_up: true, email_sign_in: true, account_creation: true };

// Sessions created by a verified email code carry a passkey-registration
// grant: the same mailbox proof a `passkey_register` code gives.
const SESSION_GRANTS: Readonly<Record<string, PasskeyRegisterGrant>> = {
  '/sign-in/email-otp': 'email_sign_in',
  '/social/email-sign-in/confirm': 'email_sign_in',
  '/sign-up/email-otp': 'account_creation',
  '/social/confirm': 'account_creation',
};

function stepUpRequired(methods: PasskeyStepUpMethod[], message: string): APIError {
  return new APIError('FORBIDDEN', { code: PASSKEY_STEP_UP_REQUIRED, message, methods });
}

async function hasStepUpPasskey(db: Pick<PrismaClient, 'passkey'>, userId: string, exceptId?: string): Promise<boolean> {
  return await db.passkey.count({
    where: { userId, countsForStepUp: true, ...(exceptId ? { id: { not: exceptId } } : {}) },
  }) > 0;
}

/** The step-up methods that can authorize this change for this user right now. */
async function availableMethods(
  db: Database, user: ResolvedSession['user'], emailAccepted: boolean,
): Promise<PasskeyStepUpMethod[]> {
  const methods: PasskeyStepUpMethod[] = [];
  if (await hasStepUpPasskey(db, user.id)) methods.push('passkey');
  if (emailAccepted && !await appleRelayEmailUndeliverable(db, user.id, user.email)) methods.push('email');
  return methods;
}

const ENROLMENT_MESSAGE = 'Verify it is you before adding a passkey.';

/** Non-consuming check that this session may start or finish a passkey enrolment. */
export async function canEnrolPasskey(db: Database, sessionId: string, userId: string, now = new Date()): Promise<boolean> {
  if (await freshStepUpPasskey(db, sessionId, userId, PASSKEY_STEP_UP_MAX_AGE_MS, now)) return true;
  const grant = await freshStepUpMarker(db, 'passkey_register', sessionId, now);
  return grant !== null && REGISTER_GRANTS[grant] === true;
}

/**
 * Authoritative enrolment check, after Better Auth has stored the verified
 * credential. Under the user's row lock it spends the step-up proof and writes
 * provenance; null means no proof applied and the caller must delete the new passkey.
 */
export async function recordPasskeyEnrolment(
  db: Database, input: { sessionId: string; userId: string; passkeyId: string }, now = new Date(),
): Promise<PasskeyEnrolmentVia | null> {
  const { sessionId, userId, passkeyId } = input;
  return db.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR UPDATE`;
    const asserted = await freshStepUpPasskey(tx, sessionId, userId, PASSKEY_STEP_UP_MAX_AGE_MS, now);
    let via: PasskeyEnrolmentVia;
    let provenAt: Date;
    if (asserted && asserted.id !== passkeyId) {
      via = 'passkey_step_up';
      provenAt = asserted.verifiedAt;
    } else {
      const grant = await consumeStepUpMarker(tx, 'passkey_register', sessionId, now);
      if (grant === null || REGISTER_GRANTS[grant] !== true) return null;
      via = grant as PasskeyRegisterGrant;
      provenAt = now;
    }
    const countsForStepUp = via === 'passkey_step_up' || !await hasStepUpPasskey(tx, userId, passkeyId);
    const updated = await tx.passkey.updateMany({
      where: { id: passkeyId, userId },
      data: { enrolledVia: via, enrolledStepUpAt: provenAt, countsForStepUp },
    });
    // Throwing rolls back the spent proof when the credential vanished.
    if (updated.count !== 1) throw new Error('enrolled passkey not found');
    return via;
  });
}

/**
 * Authorizes removing one of the user's passkeys, spending a removal code when
 * that is the proof used. Throws the typed 403 when no proof applies. A passkey
 * that is not the user's is left to Better Auth's ownership check.
 */
export async function authorizePasskeyRemoval(
  db: Database, sessionId: string, user: ResolvedSession['user'], passkeyId: string, now = new Date(),
): Promise<void> {
  const target = await db.passkey.findFirst({ where: { id: passkeyId, userId: user.id }, select: { countsForStepUp: true } });
  if (!target) return;
  if (await freshStepUpPasskey(db, sessionId, user.id, PASSKEY_STEP_UP_MAX_AGE_MS, now)) return;
  if (!target.countsForStepUp && await consumeStepUpMarker(db, 'passkey_remove', sessionId, now) !== null) return;
  throw stepUpRequired(await availableMethods(db, user, !target.countsForStepUp), 'Verify it is you before removing this passkey.');
}

export function passkeyEnrolmentPlugin(db: Database, resolveSession: SessionResolver) {
  return {
    id: 'openkey-passkey-enrolment',
    hooks: {
      before: [{
        matcher: (ctx) => ctx.path === '/passkey/generate-register-options'
          || ctx.path === '/passkey/verify-registration'
          || ctx.path === '/passkey/delete-passkey',
        handler: createAuthMiddleware(async (ctx) => {
          // No session: Better Auth's own session middleware refuses the call.
          const current = ctx.headers ? await resolveSession(ctx.headers) : null;
          if (!current) return;
          if (ctx.path === '/passkey/delete-passkey') {
            const id = (ctx.body as { id?: unknown } | undefined)?.id;
            if (typeof id === 'string') await authorizePasskeyRemoval(db, current.session.id, current.user, id);
            return;
          }
          // Enrolment also needs a Better Auth fresh session (`freshAge`). Let
          // its own refusal answer an older session, so no step-up is asked
          // for and spent on a change that would fail anyway.
          const freshAgeMs = ctx.context.sessionConfig.freshAge * 1000;
          if (freshAgeMs !== 0 && Date.now() - new Date(current.session.createdAt).getTime() >= freshAgeMs) return;
          if (await canEnrolPasskey(db, current.session.id, current.user.id)) return;
          throw stepUpRequired(await availableMethods(db, current.user, true), ENROLMENT_MESSAGE);
        }),
      }],
      after: [{
        matcher: (ctx) => ctx.path === '/passkey/verify-registration',
        handler: createAuthMiddleware(async (ctx) => {
          const created = ctx.context.returned as { id?: unknown; userId?: unknown; credentialID?: unknown } | undefined;
          const passkeyId = created?.id;
          const userId = created?.userId;
          if (typeof passkeyId !== 'string' || typeof userId !== 'string' || typeof created?.credentialID !== 'string') return;
          const remove = () => db.passkey.deleteMany({ where: { id: passkeyId, userId } });
          const current = ctx.headers ? await resolveSession(ctx.headers) : null;
          let via: PasskeyEnrolmentVia | null = null;
          if (current && current.user.id === userId) {
            try {
              via = await recordPasskeyEnrolment(db, { sessionId: current.session.id, userId, passkeyId });
            } catch (error) {
              // Not a missing proof: the credential still must not survive.
              logError('error', 'auth_passkey_enrolment_failed', error);
              await remove();
              throw new APIError('INTERNAL_SERVER_ERROR', { message: 'Could not add the passkey. Try again.' });
            }
          }
          if (via) return;
          // The proof was spent or never existed (a concurrent enrolment won,
          // or it expired mid-ceremony): the credential must not survive.
          await remove();
          throw stepUpRequired(current ? await availableMethods(db, current.user, true) : [], ENROLMENT_MESSAGE);
        }),
      }, {
        matcher: (ctx) => SESSION_GRANTS[ctx.path ?? ''] !== undefined,
        handler: createAuthMiddleware(async (ctx) => {
          const sessionId = ctx.context.newSession?.session?.id;
          if (!sessionId) return;
          await writeStepUpMarker(db, 'passkey_register', sessionId, SESSION_GRANTS[ctx.path]!);
        }),
      }],
    },
  } satisfies BetterAuthPlugin;
}

// Session-bound passkey step-up. Better Auth's passkey sign-in mints a new
// session; this verifies an assertion by a passkey that counts and stamps the
// current session instead, so a cookie session can step up in place.

const CHALLENGE_PREFIX = 'openkey-passkey-step-up-challenge';
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

function digest(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

export type RelyingParty = { rpID: string; origin: string };

export async function createPasskeyStepUpChallenge(
  db: Database, sessionId: string, userId: string, rp: RelyingParty, now = new Date(),
): Promise<{ challengeToken: string; options: PublicKeyCredentialRequestOptionsJSON } | null> {
  const passkeys = await db.passkey.findMany({
    where: { userId, countsForStepUp: true }, select: { credentialID: true, transports: true },
  });
  if (passkeys.length === 0) return null;
  const options = await generateAuthenticationOptions({
    rpID: rp.rpID,
    userVerification: 'required',
    allowCredentials: passkeys.map((passkey) => ({
      id: passkey.credentialID,
      transports: passkey.transports ? passkey.transports.split(',') as AuthenticatorTransportFuture[] : undefined,
    })),
  });
  const challengeToken = randomBytes(32).toString('base64url');
  // One outstanding challenge per session; a new request replaces the last.
  const identifier = `${CHALLENGE_PREFIX}:${sessionId}`;
  await db.$transaction([
    db.verification.deleteMany({ where: { identifier } }),
    db.verification.create({ data: {
      id: randomUUID(), identifier,
      value: JSON.stringify({ challenge: options.challenge, token: digest(challengeToken), userId }),
      expiresAt: new Date(now.getTime() + CHALLENGE_TTL_MS),
    } }),
  ]);
  return { challengeToken, options };
}

export type PasskeyStepUpResult = 'verified' | 'invalid' | 'not_step_up';

export async function verifyPasskeyStepUp(
  db: Database, sessionId: string, userId: string, body: { challengeToken?: unknown; response?: unknown } | null,
  rp: RelyingParty, now = new Date(),
): Promise<PasskeyStepUpResult> {
  const response = body?.response as AuthenticationResponseJSON | undefined;
  if (typeof body?.challengeToken !== 'string' || !response || typeof response !== 'object' || typeof response.id !== 'string') {
    return 'invalid';
  }
  const identifier = `${CHALLENGE_PREFIX}:${sessionId}`;
  const row = await db.verification.findFirst({ where: { identifier, expiresAt: { gt: now } } });
  if (!row) return 'invalid';
  // Every attempt spends the challenge, so a wrong token or assertion cannot be retried against it.
  const consumed = await db.verification.deleteMany({ where: { id: row.id, identifier, value: row.value } });
  if (consumed.count !== 1) return 'invalid';
  const stored = JSON.parse(row.value) as { challenge: string; token: string; userId: string };
  if (stored.userId !== userId || stored.token !== digest(body.challengeToken)) return 'invalid';

  const passkey = await db.passkey.findFirst({ where: { credentialID: response.id, userId } });
  if (!passkey) return 'invalid';
  if (!passkey.countsForStepUp) return 'not_step_up';
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: stored.challenge,
    expectedOrigin: rp.origin,
    expectedRPID: rp.rpID,
    credential: {
      id: passkey.credentialID,
      publicKey: new Uint8Array(Buffer.from(passkey.publicKey, 'base64')),
      counter: passkey.counter,
      transports: passkey.transports ? passkey.transports.split(',') as AuthenticatorTransportFuture[] : undefined,
    },
    requireUserVerification: true,
  }).catch(() => null);
  if (!verification?.verified || verification.authenticationInfo.userVerified !== true) return 'invalid';

  const verifiedAt = new Date();
  const stamped = await db.$transaction(async (tx) => {
    await tx.passkey.update({ where: { id: passkey.id }, data: { counter: verification.authenticationInfo.newCounter } });
    return tx.session.updateMany({
      where: { id: sessionId, userId, expiresAt: { gt: verifiedAt } },
      data: { lastPasskeyAt: verifiedAt, lastPasskeyId: passkey.id },
    });
  });
  return stamped.count === 1 ? 'verified' : 'invalid';
}
