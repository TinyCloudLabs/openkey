import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthEndpoint } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { parseUserOutput } from 'better-auth/db';
import type { AuthEndpointContext } from '@better-auth/core/context';
import type { PrismaClient } from '@openkey/db';
import { Resend } from 'resend';
import { log } from '../log';

const COOKIE = '__Host-openkey_social_email_review';
const PREFIX = 'openkey-social-email-review:';
const TTL_MS = 5 * 60 * 1000;
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

function digest(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

function invalid(): APIError {
  return new APIError('BAD_REQUEST', {
    code: 'INVALID_SOCIAL_EMAIL_REVIEW',
    message: 'This confirmation has expired. Sign in with a new email code.',
  });
}

/** Notify the verified mailbox when its social identity creates an account. */
export async function sendSocialAccountNotice(email: string, providerId: 'google' | 'apple'): Promise<void> {
  if (!resend) return;
  const provider = providerId === 'apple' ? 'Apple' : 'Google';
  try {
    const { error } = await resend.emails.send({
      from: 'OpenKey <noreply@openkey.so>',
      to: email,
      subject: `Your OpenKey account was created with ${provider}`,
      html: `<p>An OpenKey account was created using Sign in with ${provider}.</p><p>If this was not you, contact OpenKey support immediately.</p>`,
    });
    if (error) log('warn', 'auth_social_notice_failed');
  } catch {
    log('warn', 'auth_social_notice_failed');
  }
}

export function socialMailboxReview(database: PrismaClient): BetterAuthPlugin {
  return {
    id: 'openkey-social-mailbox-review',
    init: () => ({
      options: {
        databaseHooks: {
          session: {
            create: {
              before: async (session: { userId: string }, context: AuthEndpointContext | null) => {
                const user = await database.user.findUnique({
                  where: { id: session.userId },
                  select: { lockedAt: true, socialCreatedProvider: true, socialEmailReviewedAt: true },
                });
                if (user?.lockedAt) throw new APIError('FORBIDDEN', {
                  code: 'SOCIAL_ACCOUNT_LOCKED', message: 'This account is locked.',
                });
                if (context?.path !== '/sign-in/email-otp' || !user?.socialCreatedProvider || user.socialEmailReviewedAt) return;
                // A missing endpoint cookie context must not permit a session or an unbound confirmation.
                if (!context.setCookie) throw new APIError('INTERNAL_SERVER_ERROR');
                const confirmation = randomBytes(32).toString('base64url');
                const binding = randomBytes(32).toString('base64url');
                const providers = await database.account.findMany({
                  where: { userId: session.userId, providerId: { in: ['google', 'apple'] } },
                  select: { providerId: true },
                });
                await database.verification.create({ data: {
                  id: randomUUID(), userId: session.userId,
                  identifier: PREFIX + digest(confirmation), value: digest(binding),
                  expiresAt: new Date(Date.now() + TTL_MS),
                } });
                context.setCookie(COOKIE, binding, {
                  httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: TTL_MS / 1000,
                });
                log('info', 'auth_social_email_review_required');
                context.setHeader?.('Referrer-Policy', 'no-referrer');
                // This is thrown inside Better Auth's endpoint handler (not a route before-hook).
                // Its accumulated response headers, including Set-Cookie, survive the APIError.
                throw new APIError('FORBIDDEN', {
                  code: 'SOCIAL_ACCOUNT_REVIEW_REQUIRED',
                  confirmation,
                  providers: [...new Set(providers.map((account) => account.providerId))],
                });
              },
            },
          },
        },
      },
    }),
    endpoints: {
      socialEmailSignInConfirm: createAuthEndpoint('/social/email-sign-in/confirm', { method: 'POST' }, async (ctx) => {
        ctx.setHeader('Referrer-Policy', 'no-referrer');
        const body = (ctx.body ?? {}) as { confirmation?: unknown; decision?: unknown };
        const binding = ctx.getCookie(COOKIE);
        if (typeof body.confirmation !== 'string' || !binding
          || (body.decision !== 'continue' && body.decision !== 'not_mine')) throw invalid();

        // Validate the cookie before the atomic delete. A bad cookie cannot spend someone else's challenge.
        const identifier = PREFIX + digest(body.confirmation);
        const row = await database.verification.findFirst({
          where: { identifier, expiresAt: { gt: new Date() } },
          select: { id: true, userId: true, value: true },
        });
        if (!row?.userId || row.value !== digest(binding)) throw invalid();
        const now = new Date();
        const accepted = await database.$transaction(async (tx) => {
          const consumed = await tx.verification.deleteMany({
            where: { id: row.id, identifier, value: row.value, expiresAt: { gt: now } },
          });
          if (consumed.count !== 1) return false;
          const updated = await tx.user.updateMany({
            where: { id: row.userId!, socialCreatedProvider: { not: null }, socialEmailReviewedAt: null, lockedAt: null },
            data: body.decision === 'continue' ? { socialEmailReviewedAt: now } : { lockedAt: now },
          });
          if (updated.count !== 1) throw invalid(); // Roll back the challenge consumption.
          if (body.decision === 'not_mine') await tx.session.deleteMany({ where: { userId: row.userId! } });
          return true;
        });
        if (!accepted) throw invalid();
        ctx.setCookie(COOKIE, '', { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0 });
        if (body.decision === 'not_mine') {
          log('info', 'auth_social_email_review_refused');
          return ctx.json({ success: true });
        }
        const user = await ctx.context.internalAdapter.findUserById(row.userId);
        if (!user) throw invalid();
        const session = await ctx.context.internalAdapter.createSession(user.id);
        await setSessionCookie(ctx, { session, user });
        log('info', 'auth_social_email_review_confirmed');
        return ctx.json({ token: session.token, user: parseUserOutput(ctx.context.options, user) });
      }),
    },
  } satisfies BetterAuthPlugin;
}
