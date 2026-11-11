import { reviewerDeleteEndpoints } from './reviewer-delete';
import { reviewerNativeQuery } from './reviewer-native';
import type { BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthEndpoint, createAuthMiddleware, getSessionFromCtx } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { parseUserOutput } from 'better-auth/db';
import { makeSignature } from 'better-auth/crypto';
import { timingSafeEqual } from 'node:crypto';
import type { PrismaClient } from '@openkey/db';
import {
  REVIEWER_MAX_SECONDS, captureReviewer, capturedReviewer, reviewerActive, reviewerCodeMatches,
  reviewerFailure, reviewerForEmail, reviewerForUser, type ReviewerBinding,
} from './reviewer-accounts';

const REFUSAL = { code: 'REVIEWER_SIGN_IN_REFUSED', message: "Couldn't sign in with those details. Check the review account and code, then try again." };
const ALLOWED_AUTH_PATHS = new Set([
  '/get-session', '/sign-out', '/oauth2/authorize', '/oauth2/consent', '/oauth2/continue',
  '/oauth2/public-client',
  '/oauth2/token', '/oauth2/userinfo', '/oauth2/introspect', '/oauth2/revoke',
]);

function refused(): APIError {
  return new APIError('FORBIDDEN', REFUSAL);
}

export function reviewerBrowserRequest(headers: Headers, origin: string): boolean {
  return headers.get('content-type')?.split(';')[0]?.trim() === 'application/json'
    && (headers.get('origin') === origin || (!headers.has('origin') && headers.get('sec-fetch-site') === 'same-origin'));
}

export async function signedReviewerQuery(value: unknown, secret: string): Promise<URLSearchParams | null> {
  if (typeof value !== 'string' || value.length > 16384) return null;
  const query = new URLSearchParams(value);
  const seen = new Set<string>();
  for (const key of query.keys()) {
    if (seen.has(key)) return null;
    seen.add(key);
  }
  const signature = query.get('sig');
  const expiresAt = Number(query.get('exp'));
  if (!signature || !Number.isFinite(expiresAt) || expiresAt * 1000 < Date.now()) return null;
  query.delete('sig');
  const expected = await makeSignature(query.toString(), secret);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b) ? query : null;
}

export function reviewerQueryMatches(binding: ReviewerBinding, query: URLSearchParams): boolean {
  const scopes = (query.get('scope') ?? '').split(' ').filter(Boolean);
  return query.get('client_id') === binding.clientId
    && query.get('redirect_uri') === binding.redirectUri
    && query.getAll('resource').length === 1 && query.get('resource') === binding.resource
    && query.get('response_type') === 'code' && query.get('code_challenge_method') === 'S256'
    && Boolean(query.get('code_challenge')) && Boolean(query.get('state'))
    && scopes.includes('tinycloud:mcp')
    && scopes.every((scope) => ['openid', 'email', 'offline_access', 'tinycloud:mcp'].includes(scope));
}

async function reviewerContinuationMatches(database: PrismaClient, binding: ReviewerBinding, query: URLSearchParams, allowApproved = false) {
  return binding.store === 'apple' ? reviewerNativeQuery(database, binding, query, allowApproved) : reviewerQueryMatches(binding, query);
}

export function reviewerAuth(database: PrismaClient, origin: string): BetterAuthPlugin {
  async function signIn(ctx: any, earlyResponse = false) {
    const binding = await reviewerForEmail(database, ctx.body?.email);
    if (!ctx.request || !reviewerBrowserRequest(ctx.request.headers, origin)) {
      throw refused();
    }
    const cookieToken = await ctx.getSignedCookie(ctx.context.authCookies.sessionToken.name, ctx.context.secret);
    const cookieSession = cookieToken ? await ctx.context.internalAdapter.findSession(cookieToken) : null;
    const existing = cookieSession && new Date(cookieSession.session.expiresAt).getTime() > Date.now()
      ? cookieSession : await getSessionFromCtx(ctx);
    if (existing && (!binding || existing.user.id !== binding.userId)) {
      throw refused();
    }
    const query = await signedReviewerQuery(ctx.body?.oauth_query, ctx.context.secret);
    if (!binding || !query || !await reviewerContinuationMatches(database, binding, query) || !reviewerCodeMatches(binding, ctx.body?.code ?? ctx.body?.otp)) {
      await reviewerFailure(binding);
      throw refused();
    }
    captureReviewer(binding);
    const user = await ctx.context.internalAdapter.findUserById(binding.userId!);
    if (!user) throw refused();
    const session = await ctx.context.internalAdapter.createSession(user.id);
    if (!session) throw refused();
    captureReviewer(binding, session.id, new Date(session.createdAt).getTime() + REVIEWER_MAX_SECONDS * 1000);
    await setSessionCookie(ctx, { session, user }, undefined, { maxAge: REVIEWER_MAX_SECONDS });
    if (earlyResponse) {
      // Better Auth skips endpoint after-hooks for a before-hook Response, so carry
      // the cookie explicitly and resume at the provider's normal authorize entry.
      const resumed = new URLSearchParams(query);
      const prompt = (resumed.get('prompt') ?? '').split(' ').filter((value) => value !== 'login').join(' ');
      if (prompt) resumed.set('prompt', prompt);
      else resumed.delete('prompt');
      const url = ctx.context.baseURL + '/oauth2/authorize?' + resumed;
      return Response.json({ redirect: true, url }, { headers: ctx.responseHeaders });
    }
    return ctx.json({ user: parseUserOutput(ctx.context.options, user) });
  }

  return {
    id: 'openkey-reviewer-auth',
    rateLimit: [{ pathMatcher: (path) => ['/sign-in/reviewer', '/reviewer/delete-intent', '/reviewer/delete'].includes(path), window: 60, max: 3 }],
    schema: {
      oauthConsent: { fields: { reviewerEpoch: { type: 'number', required: false, input: false, returned: false } } },
    },
    hooks: {
      before: [{
        matcher: () => true,
        handler: createAuthMiddleware(async (ctx) => {
          if (['/reviewer/delete-intent', '/reviewer/delete'].includes(ctx.path)) return;
          const body = ctx.body as Record<string, unknown> | undefined;
          const binding = (body?.email ? await reviewerForEmail(database, body.email) : null)
            ?? (body?.newEmail ? await reviewerForEmail(database, body.newEmail) : null);
          if (binding) {
            if (ctx.path === '/email-otp/send-verification-otp') return ctx.json({ success: true });
            if (ctx.path === '/sign-in/email-otp') return signIn(ctx, true);
            if (ctx.path !== '/sign-in/reviewer') throw refused();
          }
          if (ctx.path === '/sign-in/reviewer') return;
          // Session reads are also used to resolve the current session within this hook.
          if (ctx.path === '/get-session') return;
          const session = await getSessionFromCtx(ctx);
          if (!session) return;
          const reviewer = await reviewerForUser(database, session.user.id);
          if (!reviewer) return;
          const source = await database.session.findUnique({ where: { id: session.session.id } });
          if (!reviewerActive(reviewer, source?.reviewerEpoch ?? null)
            || !source || source.expiresAt.getTime() <= Date.now()
            || source.createdAt.getTime() + REVIEWER_MAX_SECONDS * 1000 <= Date.now()
            || (!ALLOWED_AUTH_PATHS.has(ctx.path) && !(reviewer.store === 'apple' && ctx.request?.method === 'POST'
              && ['/oauth2/tinycloud/renew', '/oauth2/tinycloud/revoke'].includes(ctx.path)))) throw refused();
          captureReviewer(reviewer, session.session.id, source!.createdAt.getTime() + REVIEWER_MAX_SECONDS * 1000);
          if (ctx.path === '/oauth2/public-client') {
            const url = ctx.request && new URL(ctx.request.url);
            if (ctx.request?.method !== 'GET' || url?.pathname !== '/api/auth/oauth2/public-client'
              || url.searchParams.getAll('client_id').length !== 1
              || url.searchParams.get('client_id') !== reviewer.clientId) throw refused();
          }
          if (['/oauth2/authorize', '/oauth2/consent', '/oauth2/continue'].includes(ctx.path)) {
            const query = ctx.path === '/oauth2/authorize'
              ? new URLSearchParams(ctx.query as Record<string, string>)
              : await signedReviewerQuery(body?.oauth_query, ctx.context.secret);
            if (!query || !await reviewerContinuationMatches(database, reviewer, query, true)) throw refused();
          }
        }),
      }],
    },
    endpoints: {
      ...reviewerDeleteEndpoints(database, origin),
      signInReviewer: createAuthEndpoint('/sign-in/reviewer', { method: 'POST', requireHeaders: true }, (ctx) => signIn(ctx)),
    },
    init: () => ({
      options: {
        databaseHooks: {
          user: {
            create: { before: async (user: { email: string }) => {
              if (await reviewerForEmail(database, user.email)) throw refused();
            } },
            update: { before: async (user: { email?: string }) => {
              if (user.email && await reviewerForEmail(database, user.email)) throw refused();
            } },
          },
          session: {
            create: { before: async (session: { userId: string }) => {
              const binding = await reviewerForUser(database, session.userId);
              if (!binding) return;
              const captured = capturedReviewer();
              if (captured?.userId !== session.userId || !reviewerActive(binding, captured.epoch)) throw refused();
              return { data: { reviewerEpoch: captured.epoch, expiresAt: new Date(Date.now() + REVIEWER_MAX_SECONDS * 1000) } };
            } },
          },
        },
      },
    }),
  };
}
