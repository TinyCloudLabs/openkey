// TC-1114: an email OTP never creates an account silently.
//
// Better Auth's `/sign-in/email-otp` verifies (and spends) the code, then
// creates a user when none exists. The create-before hook below stops that
// one path: it issues a short-lived, single-use sign-up token bound to the
// verified email and answers NEW_ACCOUNT_CONFIRMATION_REQUIRED instead. The
// user then confirms with `/sign-up/email-otp`, which consumes the token and
// creates the account exactly as the OTP path did. Nothing about the account
// is revealed before the code is verified, so the send step is unchanged.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthEndpoint } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { parseUserOutput } from 'better-auth/db';
import type { PrismaClient } from '@openkey/db';
import { log } from '../log';

export const NEW_ACCOUNT_CONFIRMATION_REQUIRED = 'NEW_ACCOUNT_CONFIRMATION_REQUIRED';
export const INVALID_SIGNUP_TOKEN = 'INVALID_SIGNUP_TOKEN';
export const ACCOUNT_ALREADY_EXISTS = 'ACCOUNT_ALREADY_EXISTS';

// Matches the OTP lifetime: the confirmation belongs to the same sitting.
export const SIGNUP_TOKEN_TTL_MS = 5 * 60 * 1000;
const IDENTIFIER_PREFIX = 'openkey-email-signup:';

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
                const now = new Date();
                const signupToken = randomBytes(32).toString('base64url');
                await database.verification.deleteMany({
                  where: { identifier: { startsWith: IDENTIFIER_PREFIX }, expiresAt: { lte: now } },
                });
                await database.verification.create({
                  data: {
                    id: randomUUID(),
                    identifier: signupIdentifier(signupToken, user.email),
                    value: 'email-signup',
                    expiresAt: new Date(now.getTime() + SIGNUP_TOKEN_TTL_MS),
                  },
                });
                log('info', 'auth_email_signup_confirmation_required');
                throw new APIError('FORBIDDEN', {
                  code: NEW_ACCOUNT_CONFIRMATION_REQUIRED,
                  message: 'No OpenKey account exists for this email.',
                  signupToken,
                });
              },
            },
          },
        },
      },
    }),
    endpoints: {
      signUpEmailOtp: createAuthEndpoint('/sign-up/email-otp', { method: 'POST' }, async (ctx) => {
        const body = (ctx.body ?? {}) as { email?: unknown; signupToken?: unknown };
        if (typeof body.email !== 'string' || typeof body.signupToken !== 'string' || !body.signupToken) {
          log('warn', 'auth_email_signup_refused', 'signup_token_invalid');
          throw refused();
        }
        const email = body.email.toLowerCase();
        // One DELETE is the single-use gate: concurrent confirmations race on
        // the same row and only one sees it.
        const consumed = await database.verification.deleteMany({
          where: { identifier: signupIdentifier(body.signupToken, email), expiresAt: { gt: new Date() } },
        });
        if (consumed.count !== 1) {
          log('warn', 'auth_email_signup_refused', 'signup_token_invalid');
          throw refused();
        }
        if (await ctx.context.internalAdapter.findUserByEmail(email)) {
          log('warn', 'auth_email_signup_refused', 'signup_account_exists');
          throw new APIError('BAD_REQUEST', {
            code: ACCOUNT_ALREADY_EXISTS,
            message: 'An OpenKey account already exists for this email. Sign in instead.',
          });
        }
        const user = await ctx.context.internalAdapter.createUser({ email, emailVerified: true, name: '' });
        const session = await ctx.context.internalAdapter.createSession(user.id);
        await setSessionCookie(ctx, { session, user });
        log('info', 'auth_email_signup_confirmed');
        return ctx.json({ token: session.token, user: parseUserOutput(ctx.context.options, user) });
      }),
    },
  } satisfies BetterAuthPlugin;
}
