import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthEndpoint, createAuthMiddleware } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { symmetricDecrypt, symmetricEncrypt } from 'better-auth/crypto';
import { parseUserOutput } from 'better-auth/db';
import type { PrismaClient } from '@openkey/db';
import { googleCallbackProfile, type GoogleCallbackProfile } from '../social-providers';
import { log } from '../log';

const COOKIE = '__Host-openkey_social_continuation';
const PREFIX = 'openkey-google-confirm:';
const TTL_MS = 5 * 60 * 1000;

type Continuation = {
  bindingHash: string;
  nativeQueryHash?: string;
  outcome: 'new_account' | 'account_exists';
  profile: Omit<GoogleCallbackProfile, 'tokens'>;
  tokens?: GoogleCallbackProfile['tokens'];
};

function digest(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}
function invalid(): APIError {
  return new APIError('BAD_REQUEST', {
    code: 'INVALID_SOCIAL_CONFIRMATION',
    message: 'This confirmation has expired. Start Google sign-in again.',
  });
}
async function revokeGoogleToken(accessToken: string | undefined): Promise<boolean> {
  if (!accessToken) return true;
  try {
    const response = await fetch('https://oauth2.googleapis.com/revoke', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: accessToken }),
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function hasMatchingUser(database: PrismaClient, email: string): Promise<boolean> {
  const rows = await database.$queryRaw<{ id: string }[]>`
    SELECT id FROM "user" WHERE LOWER(email) = LOWER(${email}) LIMIT 1
  `;
  return rows.length > 0;
}

export function googleSocialConfirmation(database: PrismaClient) {
  async function sweepExpired(key: Parameters<typeof symmetricDecrypt>[0]['key']) {
    const expired = await database.verification.findMany({
      where: { identifier: { startsWith: PREFIX }, expiresAt: { lte: new Date() } },
    });
    for (const row of expired) {
      try {
        const stored = JSON.parse(await symmetricDecrypt({ key, data: row.value })) as Continuation;
        if (stored.outcome === 'new_account' && stored.tokens?.accessToken) {
          const linked = await database.account.findFirst({
            where: { providerId: 'google', accountId: stored.profile.id }, select: { id: true },
          });
          if (!linked && !await revokeGoogleToken(stored.tokens.accessToken)) continue;
        }
      } catch {
        log('warn', 'auth_google_continuation_cleanup_failed');
        continue;
      }
      await database.verification.deleteMany({ where: { id: row.id } });
    }
  }
  let sweeping = false;
  let sweepStarted = false;
  function scheduleSweep(key: Parameters<typeof symmetricDecrypt>[0]['key']) {
    if (sweepStarted) return;
    sweepStarted = true;
    const timer = setInterval(async () => {
      if (sweeping) return;
      sweeping = true;
      try { await sweepExpired(key); } catch { log('warn', 'auth_google_continuation_cleanup_failed'); }
      finally { sweeping = false; }
    }, 60_000);
    timer.unref();
  }

  return {
    id: 'openkey-google-social-confirmation',
    hooks: {
      after: [{
        matcher: (ctx) => ctx.path === '/callback/:id',
        handler: createAuthMiddleware(async (ctx) => {
          if (ctx.params?.id !== 'google') return;
          const location = ctx.context.responseHeaders?.get('location');
          if (!location) return;
          let target: URL;
          try { target = new URL(location); } catch { return; }
          if (target.origin !== new URL(process.env.WEBAUTHN_ORIGIN!).origin) return;
          const error = target.searchParams.get('error');
          if (error !== 'signup_disabled' && error !== 'account_not_linked') return;
          const profile = await googleCallbackProfile.get();
          if (!profile) return; // No verified profile from the token exchange.
          scheduleSweep(ctx.context.secretConfig);
          const outcome = error === 'account_not_linked' || await hasMatchingUser(database, profile.email)
            ? 'account_exists' : 'new_account';
          if (outcome === 'account_exists' && !await revokeGoogleToken(profile.tokens.accessToken)) {
            log('warn', 'auth_google_token_revoke_failed');
          }
          const token = randomBytes(32).toString('base64url');
          const nativeQuery = new URLSearchParams(target.searchParams);
          nativeQuery.delete('error');
          nativeQuery.delete('native_social_error');
          const nativeQueryHash = nativeQuery.has('tinycloud_request') ? digest(nativeQuery.toString()) : undefined;
          const binding = randomBytes(32).toString('base64url');
          const { tokens, ...displayProfile } = profile;
          const stored: Continuation = {
            bindingHash: digest(binding), outcome, profile: displayProfile,
            ...(nativeQueryHash ? { nativeQueryHash } : {}),
            ...(outcome === 'new_account' ? { tokens } : {}),
          };
          await database.verification.create({ data: {
            id: randomUUID(), identifier: PREFIX + digest(token),
            value: await symmetricEncrypt({ key: ctx.context.secretConfig, data: JSON.stringify(stored) }),
            expiresAt: new Date(Date.now() + TTL_MS),
          } });
          ctx.setCookie(COOKIE, binding, {
            httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: TTL_MS / 1000,
          });
          target.searchParams.set('error', outcome);
          target.searchParams.set('continuation', token);
          ctx.setHeader('location', target.href);
          ctx.setHeader('Referrer-Policy', 'no-referrer');
        }),
      }],
    },
    endpoints: {
      socialContinuation: createAuthEndpoint('/social/continuation', { method: 'GET' }, async (ctx) => {
        ctx.setHeader('Referrer-Policy', 'no-referrer');
        const token = ctx.query?.continuation;
        const binding = ctx.getCookie(COOKIE);
        if (typeof token !== 'string' || !binding) throw invalid();
        const row = await database.verification.findFirst({
          where: { identifier: PREFIX + digest(token), expiresAt: { gt: new Date() } },
        });
        if (!row) throw invalid();
        const stored = JSON.parse(await symmetricDecrypt({ key: ctx.context.secretConfig, data: row.value })) as Continuation;
        if (stored.bindingHash !== digest(binding)
          || (stored.nativeQueryHash && (typeof ctx.query?.oauthQuery !== 'string'
            || digest(ctx.query.oauthQuery) !== stored.nativeQueryHash))) throw invalid();
        return ctx.json({ outcome: stored.outcome, email: stored.profile.email, name: stored.profile.name });
      }),
      socialConfirm: createAuthEndpoint('/social/confirm', { method: 'POST' }, async (ctx) => {
        ctx.setHeader('Referrer-Policy', 'no-referrer');
        const body = (ctx.body ?? {}) as { continuation?: unknown; oauthQuery?: unknown };
        const token = body.continuation;
        const binding = ctx.getCookie(COOKIE);
        if (typeof token !== 'string' || !binding) throw invalid();
        const row = await database.verification.findFirst({
          where: { identifier: PREFIX + digest(token), expiresAt: { gt: new Date() } },
        });
        if (!row) throw invalid();
        const stored = JSON.parse(await symmetricDecrypt({ key: ctx.context.secretConfig, data: row.value })) as Continuation;
        if (stored.bindingHash !== digest(binding) || stored.outcome !== 'new_account' || !stored.tokens
          || (stored.nativeQueryHash && (typeof body.oauthQuery !== 'string'
            || digest(body.oauthQuery) !== stored.nativeQueryHash))) throw invalid();
        const consumed = await database.verification.deleteMany({
          where: { id: row.id, value: row.value, expiresAt: { gt: new Date() } },
        });
        if (consumed.count !== 1) throw invalid();
        ctx.setCookie(COOKIE, '', { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0 });
        const { profile, tokens } = stored;
        if (await hasMatchingUser(database, profile.email)) {
          throw new APIError('BAD_REQUEST', { code: 'ACCOUNT_ALREADY_EXISTS', message: 'Sign in to your existing OpenKey account.' });
        }
        let created;
        try {
          created = await ctx.context.internalAdapter.createOAuthUser({
            email: profile.email, emailVerified: true, name: profile.name, image: profile.image,
          }, {
            providerId: 'google', accountId: profile.id,
            accessToken: tokens.accessToken && await symmetricEncrypt({ key: ctx.context.secretConfig, data: tokens.accessToken }),
            refreshToken: tokens.refreshToken && await symmetricEncrypt({ key: ctx.context.secretConfig, data: tokens.refreshToken }),
            idToken: tokens.idToken,
            accessTokenExpiresAt: tokens.accessTokenExpiresAt ? new Date(tokens.accessTokenExpiresAt) : undefined,
            refreshTokenExpiresAt: tokens.refreshTokenExpiresAt ? new Date(tokens.refreshTokenExpiresAt) : undefined,
            scope: tokens.scope,
          });
        } catch (error) {
          if (await hasMatchingUser(database, profile.email)) {
            throw new APIError('BAD_REQUEST', { code: 'ACCOUNT_ALREADY_EXISTS', message: 'Sign in to your existing OpenKey account.' });
          }
          if (await database.account.findFirst({
            where: { providerId: 'google', accountId: profile.id }, select: { id: true },
          })) {
            throw new APIError('BAD_REQUEST', { code: 'ACCOUNT_ALREADY_LINKED', message: 'This Google identity is already linked.' });
          }
          throw error;
        }
        const session = await ctx.context.internalAdapter.createSession(created.user.id);
        await setSessionCookie(ctx, { session, user: created.user });
        log('info', 'auth_google_signup_confirmed');
        return ctx.json({ token: session.token, user: parseUserOutput(ctx.context.options, created.user) });
      }),
    },
  } satisfies BetterAuthPlugin;
}
