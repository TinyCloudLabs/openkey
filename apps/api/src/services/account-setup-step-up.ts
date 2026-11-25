// The email-code confirmation of an account setup, for an account with no passkey that counts for step-up.
//
// The one file between the account setup routes and the email code store: the routes call only these two functions,
// so moving the grade onto a shared single-statement grader touches this file alone. Until it is built, every call
// refuses: no code is sent and no code matches.
import type { PrismaClient } from '@openkey/db';

type StepUpDatabase = Pick<PrismaClient, 'verification' | '$transaction' | '$queryRaw' | '$executeRaw'>;

/** Mails a code bound to this session and this setup request. */
export async function sendAccountSetupCode(
  _db: StepUpDatabase, _input: { sessionId: string; requestId: string; email: string },
): Promise<'sent' | 'pending' | 'unavailable'> {
  return 'unavailable';
}

/** Grades a code for this session and setup request in one statement: a match spends the code, a miss spends an attempt. */
export async function gradeAccountSetupCode(
  _db: StepUpDatabase, _input: { sessionId: string; requestId: string; code: unknown },
): Promise<'match' | 'mismatch' | 'missing'> {
  return 'missing';
}
