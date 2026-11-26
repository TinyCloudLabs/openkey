// One email code signs in exactly once, and every wrong guess costs an attempt.
//
// Better Auth 1.6.10 verifies a code by reading the verification row, deleting it without checking how
// many rows the delete removed, and only then comparing (`plugins/email-otp/routes.mjs`,
// `atomicVerifyOTP`). Concurrent requests all read the row before any delete lands, so one valid code
// creates as many sessions as there are requests, and parallel wrong guesses are all evaluated while
// their failed-attempt increments overwrite each other. `allowedAttempts` bounds nothing under
// concurrency.
//
// This hook grades the code ahead of Better Auth in a single SQL statement: one locked row, one
// decision, and either the row is spent or its attempt count rises -- never both, never lost. The one
// request that consumes a code hands Better Auth a fresh single-use value in place of the code, so Better
// Auth's own non-atomic verification can only ever succeed for that request.
import { randomBytes, randomUUID } from 'node:crypto';
import type { BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthMiddleware } from 'better-auth/api';
import type { PrismaClient } from '@openkey/db';
import { signInCodeStorage } from './email-code-storage';

/** Wrong guesses allowed per code, shared with the `emailOTP` plugin so the two cannot drift. */
export const EMAIL_CODE_ALLOWED_ATTEMPTS = 3;

/**
 * The single-use value handed to Better Auth after a code is consumed. The prefix keeps these rows out
 * of grading, so a later request can neither spend one nor spend its attempts.
 */
const HANDOFF_ID_PREFIX = 'otp-handoff-';

/** Code types stored as `<type>-otp-<email>`; `change-email` keys on two addresses and is not graded here. */
const GRADED_TYPES: Record<string, true> = { 'sign-in': true, 'email-verification': true, 'forget-password': true };

type VerifyingPath = {
  /** The code type the path verifies, or null when the request body names it. */
  otpType: string | null;
  /** Whether a correct code is spent by the request. */
  consume: boolean;
};

/** Every Better Auth path that compares a submitted code with a stored one. */
const VERIFYING_PATHS: Record<string, VerifyingPath> = {
  '/sign-in/email-otp': { otpType: 'sign-in', consume: true },
  '/email-otp/verify-email': { otpType: 'email-verification', consume: true },
  '/email-otp/reset-password': { otpType: 'forget-password', consume: true },
  // Reports whether a code is right without spending it; only its attempt count has to be atomic.
  '/email-otp/check-verification-otp': { otpType: null, consume: false },
};

type Grade = {
  matched: boolean;
  expired: boolean;
  exhausted: boolean;
  attempts: number;
  expiresAt: Date;
};

/**
 * Grades one submitted code and records the outcome in the same statement.
 *
 * A resend adds a row rather than replacing one (`resendStrategy: 'rotate'`), so an identifier can hold
 * several codes. Only the newest is ever graded. `FOR UPDATE` serializes concurrent graders on it, so
 * each sees the attempt count every earlier request left behind. Then either the code is spent (right,
 * expired, or out of attempts) and **every** non-handoff row for the identifier goes with it, the way
 * Better Auth's own delete-by-identifier would, or the graded row's attempt count rises. Deleting only
 * the graded row would promote a superseded code and hand the caller a fresh set of attempts.
 *
 * Returns the decision, or null when no code is stored for the identifier.
 */
async function gradeEmailCode(database: PrismaClient, input: {
  identifier: string;
  digest: string;
  consume: boolean;
}): Promise<Grade | null> {
  const now = new Date();
  const rows = await database.$queryRaw<Grade[]>`
    WITH target AS (
      SELECT "id", "value", "expiresAt"
        FROM "verification"
       WHERE "identifier" = ${input.identifier}
         AND "id" NOT LIKE ${`${HANDOFF_ID_PREFIX}%`}
       ORDER BY "createdAt" DESC
       LIMIT 1
       FOR UPDATE
    ),
    graded AS (
      SELECT "id",
             "expiresAt",
             "expiresAt" <= ${now} AS expired,
             regexp_replace("value", ':[0-9]+$', '') AS code_digest,
             regexp_replace("value", ':[0-9]+$', '') = ${input.digest} AS matched,
             COALESCE(substring("value" FROM ':([0-9]+)$'), '0')::int AS attempts,
             COALESCE(substring("value" FROM ':([0-9]+)$'), '0')::int >= ${EMAIL_CODE_ALLOWED_ATTEMPTS}::int AS exhausted
        FROM target
    ),
    spent AS (
      DELETE FROM "verification"
       WHERE "identifier" = ${input.identifier}
         AND "id" NOT LIKE ${`${HANDOFF_ID_PREFIX}%`}
         AND EXISTS (
           SELECT 1 FROM graded
            WHERE expired OR exhausted OR (matched AND ${input.consume}::boolean)
         )
      RETURNING "id"
    ),
    counted AS (
      UPDATE "verification" AS v
         SET "value" = g.code_digest || ':' || (g.attempts + 1)::text,
             "updatedAt" = ${now}
        FROM graded g
       WHERE v."id" = g."id" AND NOT g.expired AND NOT g.exhausted AND NOT g.matched
      RETURNING v."id"
    )
    SELECT matched, expired, exhausted, attempts, "expiresAt" FROM graded
  `;
  return rows[0] ?? null;
}

/** Better Auth's own refusals, so a caller sees one contract whichever layer answers. */
function invalidOtp(): APIError {
  return new APIError('BAD_REQUEST', { code: 'INVALID_OTP', message: 'Invalid OTP' });
}

export function emailCodeAtomicVerify(database: PrismaClient) {
  return {
    id: 'openkey-email-code-atomic-verify',
    hooks: {
      before: [{
        matcher: (ctx) => Object.hasOwn(VERIFYING_PATHS, ctx.path),
        handler: createAuthMiddleware(async (ctx) => {
          const route = VERIFYING_PATHS[ctx.path];
          const body = ctx.body as { email?: unknown; otp?: unknown; type?: unknown } | undefined;
          if (!route || typeof body?.email !== 'string' || typeof body.otp !== 'string') return;
          // Better Auth lowercases the address before building the identifier; an unknown type is left
          // to its own body validation.
          const otpType = route.otpType ?? (typeof body.type === 'string' ? body.type : '');
          if (!Object.hasOwn(GRADED_TYPES, otpType)) return;
          const identifier = `${otpType}-otp-${body.email.toLowerCase()}`;

          const grade = await gradeEmailCode(database, {
            identifier,
            digest: await signInCodeStorage.hash(body.otp),
            consume: route.consume,
          });
          if (!grade) throw invalidOtp();
          if (grade.expired) throw new APIError('BAD_REQUEST', { code: 'OTP_EXPIRED', message: 'OTP expired' });
          if (grade.exhausted) {
            throw new APIError('FORBIDDEN', { code: 'TOO_MANY_ATTEMPTS', message: 'Too many attempts' });
          }
          if (!grade.matched) throw invalidOtp();
          // A check leaves the code in place; Better Auth re-reads the same row and agrees.
          if (!route.consume) return;

          // The code is spent. Better Auth still verifies before it signs in, so give it a value only
          // this request knows, under the identifier it will look up.
          const handoff = randomBytes(32).toString('base64url');
          await database.verification.create({
            data: {
              id: `${HANDOFF_ID_PREFIX}${randomUUID()}`,
              identifier,
              value: `${await signInCodeStorage.hash(handoff)}:0`,
              expiresAt: grade.expiresAt,
            },
          });
          return { context: { body: { ...body, otp: handoff } } };
        }),
      }],
    },
  } satisfies BetterAuthPlugin;
}
