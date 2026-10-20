// TC-1114: an email OTP never creates an account silently.
//
// Better Auth's `/sign-in/email-otp` verifies (and spends) the code, then
// creates a user when none exists. The create-before hook below stops that
// one path: it issues a short-lived, single-use sign-up token bound to the
// verified email and answers NEW_ACCOUNT_CONFIRMATION_REQUIRED instead. The
// user then confirms with `/sign-up/email-otp`, which consumes the token and
// creates the account exactly as the OTP path did. Nothing about the account
// is revealed before the code is verified, so the send step is unchanged.
//
// TC-1632: confirmation also requires a Cloudflare Turnstile token, verified
// with siteverify before the token is consumed. A QA registration secret,
// checked on the OTP step, marks the token so the Turnstile step is skipped.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthEndpoint } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { parseUserOutput } from 'better-auth/db';
import { getCurrentAuthContext } from '@better-auth/core/context';
import type { PrismaClient } from '@openkey/db';
import { log } from '../log';
import { QA_REGISTRATION_HEADER, qaRegistrationAuthorized } from './qa-registration';
import { verifyTurnstileToken } from './turnstile';

export const NEW_ACCOUNT_CONFIRMATION_REQUIRED = 'NEW_ACCOUNT_CONFIRMATION_REQUIRED';
export const INVALID_SIGNUP_TOKEN = 'INVALID_SIGNUP_TOKEN';
export const ACCOUNT_ALREADY_EXISTS = 'ACCOUNT_ALREADY_EXISTS';
export const TURNSTILE_REQUIRED = 'TURNSTILE_REQUIRED';
export const TURNSTILE_FAILED = 'TURNSTILE_FAILED';
export const REGISTRATION_PAUSED = 'REGISTRATION_PAUSED';

// Matches the OTP lifetime: the confirmation belongs to the same sitting.
export const SIGNUP_TOKEN_TTL_MS = 5 * 60 * 1000;
const IDENTIFIER_PREFIX = 'openkey-email-signup:';
// Stored in `verification.value`. A token carrying this value skips siteverify.
const VALUE_CHALLENGED = 'email-signup';
const VALUE_QA_EXEMPT = 'email-signup-qa';

/**
 * Only a hash is stored, and it covers the email: a token presented with any
 * other email matches no row.
 */
function signupIdentifier(token: string, email: string): string {
  return IDENTIFIER_PREFIX + createHash('sha256').update(`${token}\n${email}`).digest('base64url');
}

function refused(): APIError {
  return new APIError('BAD_REQUEST', {
    code: INVALID_SIGNUP_TOKEN,
    message: 'This confirmation has expired. Request a new code to create your account.',
  });
}

// Read from the request on the OTP step only. A missing request context means
// no QA header, so the normal Turnstile path applies.
async function presentedQaSecret(): Promise<string | null> {
  try {
    const ctx = await getCurrentAuthContext();
    return ctx.request?.headers.get(QA_REGISTRATION_HEADER) ?? null;
  } catch {
    return null;
  }
}

// Verifies the widget token. Only a definite success passes. A refused token
// leaves the sign-up token unspent so the visitor can complete the check again.
async function requireTurnstile(token: unknown): Promise<void> {
  if (typeof token !== 'string' || !token) {
    log('warn', 'auth_email_signup_turnstile_refused', 'turnstile_required');
    throw new APIError('BAD_REQUEST', {
      code: TURNSTILE_REQUIRED,
      message: 'Complete the verification check to create your account.',
    });
  }
  const outcome = await verifyTurnstileToken(token);
  if (outcome === 'success') {
    log('info', 'auth_email_signup_turnstile_verified');
    return;
  }
  if (outcome === 'rejected') {
    log('warn', 'auth_email_signup_turnstile_refused', 'turnstile_failed');
    throw new APIError('BAD_REQUEST', {
      code: TURNSTILE_FAILED,
      message: 'Verification failed. Complete the check again.',
    });
  }
  // Fail closed: the check could not run, so no account is created.
  log('error', 'auth_email_signup_turnstile_unavailable', 'turnstile_unavailable');
  throw new APIError('SERVICE_UNAVAILABLE', {
    code: REGISTRATION_PAUSED,
    message: 'Sign-ups are paused for a moment. Try again shortly.',
  });
}

export function emailSignupConfirmation(database: PrismaClient) {
  return {
    id: 'openkey-email-signup-confirmation',
    init: () => ({
      options: {
        databaseHooks: {
          user: {
            create: {
              before: async (user: { email: string }, context: { path?: string } | null) => {
                if (context?.path !== '/sign-in/email-otp') return;
                const qaExempt = qaRegistrationAuthorized(await presentedQaSecret());
                const now = new Date();
                const signupToken = randomBytes(32).toString('base64url');
                await database.verification.deleteMany({
                  where: { identifier: { startsWith: IDENTIFIER_PREFIX }, expiresAt: { lte: now } },
                });
                await database.verification.create({
                  data: {
                    id: randomUUID(),
                    identifier: signupIdentifier(signupToken, user.email),
                    value: qaExempt ? VALUE_QA_EXEMPT : VALUE_CHALLENGED,
                    expiresAt: new Date(now.getTime() + SIGNUP_TOKEN_TTL_MS),
                  },
                });
                log('info', qaExempt ? 'auth_email_signup_qa_exempt' : 'auth_email_signup_confirmation_required');
                throw new APIError('FORBIDDEN', {
                  code: NEW_ACCOUNT_CONFIRMATION_REQUIRED,
                  message: 'No OpenKey account exists for this email.',
                  signupToken,
                  turnstileRequired: !qaExempt,
                });
              },
            },
          },
        },
      },
    }),
    endpoints: {
      signUpEmailOtp: createAuthEndpoint('/sign-up/email-otp', { method: 'POST' }, async (ctx) => {
        const body = (ctx.body ?? {}) as { email?: unknown; signupToken?: unknown; turnstileToken?: unknown };
        if (typeof body.email !== 'string' || typeof body.signupToken !== 'string' || !body.signupToken) {
          log('warn', 'auth_email_signup_refused', 'signup_token_invalid');
          throw refused();
        }
        const email = body.email.toLowerCase();
        const identifier = signupIdentifier(body.signupToken, email);
        // Read without spending: a failed Turnstile check must leave the token usable.
        const pending = await database.verification.findFirst({
          where: { identifier, expiresAt: { gt: new Date() } },
          select: { id: true, value: true },
        });
        if (!pending) {
          log('warn', 'auth_email_signup_refused', 'signup_token_invalid');
          throw refused();
        }
        if (pending.value !== VALUE_QA_EXEMPT) await requireTurnstile(body.turnstileToken);
        // One DELETE is the single-use gate: concurrent confirmations race on
        // the same row and only one sees it.
        const consumed = await database.verification.deleteMany({ where: { id: pending.id } });
        if (consumed.count !== 1) {
          log('warn', 'auth_email_signup_refused', 'signup_token_invalid');
          throw refused();
        }
        const accountExists = () => {
          log('warn', 'auth_email_signup_refused', 'signup_account_exists');
          return new APIError('BAD_REQUEST', {
            code: ACCOUNT_ALREADY_EXISTS,
            message: 'An OpenKey account already exists for this email. Sign in instead.',
          });
        };
        if (await ctx.context.internalAdapter.findUserByEmail(email)) throw accountExists();
        let user;
        try {
          user = await ctx.context.internalAdapter.createUser({ email, emailVerified: true, name: '' });
        } catch (error) {
          // A concurrent sign-up for the same email (a second verified code,
          // or social sign-in) won the unique email constraint.
          if (await ctx.context.internalAdapter.findUserByEmail(email)) throw accountExists();
          throw error;
        }
        const session = await ctx.context.internalAdapter.createSession(user.id);
        await setSessionCookie(ctx, { session, user });
        log('info', 'auth_email_signup_confirmed');
        return ctx.json({ token: session.token, user: parseUserOutput(ctx.context.options, user) });
      }),
    },
  } satisfies BetterAuthPlugin;
}
