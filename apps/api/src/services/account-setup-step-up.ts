// The email-code confirmation of an account setup, for an account with no passkey that counts for step-up.
//
// The one file between the account setup routes and the email code store: the routes call only these two functions,
// so moving the grade onto a shared single-statement grader touches this file alone. The grade has the semantics of
// the sign-in code grader (email-code-atomic-verify.ts): three wrong guesses, the newest code only, one locked row
// and one decision per statement; a right code is spent by the request that matched it.
import { randomInt, randomUUID } from 'node:crypto';
import { Resend } from 'resend';
import type { PrismaClient } from '@openkey/db';
import { stepUpCodeDigest } from './email-code-storage';

const TTL_MS = 5 * 60 * 1000;
/** Wrong guesses allowed per code: the sign-in grader's `EMAIL_CODE_ALLOWED_ATTEMPTS`. */
export const ACCOUNT_SETUP_CODE_ATTEMPTS = 3;
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const isDev = process.env.NODE_ENV !== 'production' && process.env.TEE_MODE !== 'production';

type StepUpDatabase = Pick<PrismaClient, 'verification' | '$transaction' | '$queryRaw'>;

/** One code per session and setup request. */
export function accountSetupCodeIdentifier(sessionId: string, requestId: string): string {
  return `account-setup-otp:${sessionId}:${requestId}`;
}

/**
 * Mails a code bound to this session and this setup request. `pending` while an earlier code for the same request is
 * unexpired: no second code is mailed. The session row lock orders concurrent sends (the account step-up sender's
 * shape).
 */
export async function sendAccountSetupCode(
  db: StepUpDatabase, input: { sessionId: string; requestId: string; email: string },
): Promise<'sent' | 'pending' | 'unavailable'> {
  if (!resend && !isDev) return 'unavailable';
  const identifier = accountSetupCodeIdentifier(input.sessionId, input.requestId);
  const now = new Date();
  const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
  const digest = stepUpCodeDigest(identifier, code);
  const issued = await db.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "session" WHERE id = ${input.sessionId} FOR UPDATE`;
    const existing = await tx.verification.findFirst({ where: { identifier, expiresAt: { gt: now } } });
    if (existing) return false;
    await tx.verification.deleteMany({ where: { identifier } });
    await tx.verification.create({ data: {
      id: randomUUID(), identifier, value: `${digest}:0`, expiresAt: new Date(now.getTime() + TTL_MS),
    } });
    return true;
  });
  if (!issued) return 'pending';
  if (resend) {
    try {
      const result = await resend.emails.send({
        from: 'OpenKey <noreply@openkey.so>',
        to: input.email,
        subject: 'Your code to set up your TinyCloud account',
        html: `<p>Use this code to set up your TinyCloud account in OpenKey:</p><p>${code}</p><p>It expires in 5 minutes. If you didn't ask for this, don't share the code. You can ignore this email.</p>`,
      });
      if (result.error) throw result.error;
    } catch {
      await db.verification.deleteMany({ where: { identifier, value: `${digest}:0` } });
      return 'unavailable';
    }
  }
  return 'sent';
}

/**
 * Grades a code for this session and setup request in one statement. `match` spends the code; a wrong code costs an
 * attempt; an expired code or one out of attempts is deleted (`missing` from then on).
 */
export async function gradeAccountSetupCode(
  db: StepUpDatabase, input: { sessionId: string; requestId: string; code: unknown },
): Promise<'match' | 'mismatch' | 'missing'> {
  if (typeof input.code !== 'string' || !/^\d{6}$/.test(input.code)) return 'mismatch';
  const identifier = accountSetupCodeIdentifier(input.sessionId, input.requestId);
  const digest = stepUpCodeDigest(identifier, input.code);
  const now = new Date();
  const rows = await db.$queryRaw<{ matched: boolean; expired: boolean; exhausted: boolean }[]>`
    WITH target AS (
      SELECT "id", "value", "expiresAt"
        FROM "verification"
       WHERE "identifier" = ${identifier}
       ORDER BY "createdAt" DESC
       LIMIT 1
       FOR UPDATE
    ),
    graded AS (
      SELECT "id",
             "expiresAt" <= ${now} AS expired,
             regexp_replace("value", ':[0-9]+$', '') AS code_digest,
             regexp_replace("value", ':[0-9]+$', '') = ${digest} AS matched,
             COALESCE(substring("value" FROM ':([0-9]+)$'), '0')::int AS attempts,
             COALESCE(substring("value" FROM ':([0-9]+)$'), '0')::int >= ${ACCOUNT_SETUP_CODE_ATTEMPTS}::int AS exhausted
        FROM target
    ),
    spent AS (
      DELETE FROM "verification"
       WHERE "identifier" = ${identifier}
         AND EXISTS (SELECT 1 FROM graded WHERE expired OR exhausted OR matched)
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
    SELECT matched, expired, exhausted FROM graded
  `;
  const grade = rows[0];
  if (!grade || grade.expired || grade.exhausted) return 'missing';
  return grade.matched ? 'match' : 'mismatch';
}
