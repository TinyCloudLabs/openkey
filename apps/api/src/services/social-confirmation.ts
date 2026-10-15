import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthEndpoint, createAuthMiddleware } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { symmetricDecrypt, symmetricEncrypt } from 'better-auth/crypto';
import { parseUserOutput } from 'better-auth/db';
import type { PrismaClient } from '@openkey/db';
import { defineRequestState } from '@better-auth/core/context';
import {
  appleCallbackProfile, appleTokenClientId, googleCallbackProfile, configuredSocialProviderIds, generateAppleClientSecret,
  type AppleCallbackProfile, type GoogleCallbackProfile, type SocialProviderId,
} from '../social-providers';
import { sendSocialAccountNotice } from './social-mailbox-review';
import { log } from '../log';

const COOKIE = '__Host-openkey_social_continuation';
const PREFIX: Record<SocialProviderId, string> = {
  google: 'openkey-google-confirm:',
  apple: 'openkey-apple-confirm:',
};
const TTL_MS = 5 * 60 * 1000;
export const confirmedSocialProvider = defineRequestState<SocialProviderId | undefined>(() => undefined);

type CallbackProfile = GoogleCallbackProfile | AppleCallbackProfile;
type StoredProfile = Omit<GoogleCallbackProfile, 'tokens'> & {
  clientId?: string;
  isPrivateEmail?: boolean;
};
type Continuation = {
  providerId: SocialProviderId;
  bindingHash: string;
  nativeQueryHash?: string;
  outcome: 'new_account' | 'account_exists';
  profile: StoredProfile;
  tokens?: CallbackProfile['tokens'];
};

function digest(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}
function invalid(): APIError {
  return new APIError('BAD_REQUEST', {
    code: 'INVALID_SOCIAL_CONFIRMATION',
    message: 'This confirmation has expired. Start social sign-in again.',
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

export async function revokeAppleToken(token: string | undefined, clientId: string | undefined): Promise<boolean> {
  if (!token) return true;
  if (!clientId || !process.env.APPLE_TEAM_ID || !process.env.APPLE_KEY_ID || !process.env.APPLE_PRIVATE_KEY) return false;
  try {
    const response = await fetch('https://appleid.apple.com/auth/revoke', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token, token_type_hint: 'refresh_token', client_id: clientId,
        client_secret: await generateAppleClientSecret(
          clientId, process.env.APPLE_TEAM_ID, process.env.APPLE_KEY_ID, process.env.APPLE_PRIVATE_KEY,
        ),
      }),
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function revokeAbandoned(stored: Continuation): Promise<boolean> {
  if (stored.providerId === 'apple') {
    return revokeAppleToken(stored.tokens?.refreshToken ?? stored.tokens?.accessToken, stored.profile.clientId);
  }
  return revokeGoogleToken(stored.tokens?.accessToken);
}

async function hasMatchingUser(database: PrismaClient, email: string): Promise<boolean> {
  const rows = await database.$queryRaw<{ id: string }[]>`
    SELECT id FROM "user" WHERE LOWER(email) = LOWER(${email}) LIMIT 1
  `;
  return rows.length > 0;
}

export function socialConfirmation(database: PrismaClient) {
  async function sweepExpired(key: Parameters<typeof symmetricDecrypt>[0]['key']) {
    const expired = await database.verification.findMany({
      where: {
        OR: [
          { identifier: { startsWith: PREFIX.google } },
          { identifier: { startsWith: PREFIX.apple } },
        ],
        expiresAt: { lte: new Date() },
      },
    });
    for (const row of expired) {
      try {
        const stored = JSON.parse(await symmetricDecrypt({ key, data: row.value })) as Continuation;
        if (stored.tokens && (stored.outcome === 'new_account' || stored.providerId === 'apple')) {
          const linked = await database.account.findFirst({
            where: { providerId: stored.providerId, accountId: stored.profile.id }, select: { id: true },
          });
          if (!linked && !await revokeAbandoned(stored)) continue;
        }
      } catch {
        log('warn', 'auth_social_continuation_cleanup_failed');
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
      try { await sweepExpired(key); } catch { log('warn', 'auth_social_continuation_cleanup_failed'); }
      finally { sweeping = false; }
    }, 60_000);
    timer.unref();
  }

  return {
    id: 'openkey-social-confirmation',
    hooks: {
      after: [{
        matcher: (ctx) => ctx.path === '/callback/:id',
        handler: createAuthMiddleware(async (ctx) => {
          const providerId: unknown = ctx.params?.id;
          if (providerId !== 'google' && providerId !== 'apple') return;
          const location = ctx.context.responseHeaders?.get('location');
          if (!location) return;
          let target: URL;
          try { target = new URL(location); } catch { return; }
          if (target.origin !== new URL(process.env.WEBAUTHN_ORIGIN!).origin) return;
          const error = target.searchParams.get('error');
          if (providerId === 'apple' && error === 'email_not_found') {
            target.searchParams.set('error', 'apple_email_required');
            ctx.setHeader('location', target.href);
            return;
          }
          if (error !== 'signup_disabled' && error !== 'account_not_linked') return;
          const profile = providerId === 'google'
            ? await googleCallbackProfile.get() : await appleCallbackProfile.get();
          if (!profile) return; // No verified profile from the token exchange.
          scheduleSweep(ctx.context.secretConfig);
          const outcome = error === 'account_not_linked' || await hasMatchingUser(database, profile.email)
            ? 'account_exists' : 'new_account';
          let retainAppleTokens = false;
          if (outcome === 'account_exists') {
            const linkedApple = providerId === 'apple' && await database.account.findFirst({
              where: { providerId, accountId: profile.id }, select: { id: true },
            });
            if (!linkedApple && !await revokeAbandoned({
              providerId, bindingHash: '', outcome, profile, tokens: profile.tokens,
            })) {
              log('warn', 'auth_social_token_revoke_failed');
              retainAppleTokens = providerId === 'apple';
            }
          }
          const token = randomBytes(32).toString('base64url');
          const nativeQuery = new URLSearchParams(target.searchParams);
          nativeQuery.delete('error');
          nativeQuery.delete('native_social_error');
          const nativeQueryHash = nativeQuery.has('tinycloud_request') ? digest(nativeQuery.toString()) : undefined;
          const binding = randomBytes(32).toString('base64url');
          const { tokens, ...displayProfile } = profile;
          const stored: Continuation = {
            providerId, bindingHash: digest(binding), outcome, profile: displayProfile,
            ...(nativeQueryHash ? { nativeQueryHash } : {}),
            ...(outcome === 'new_account' || retainAppleTokens ? { tokens } : {}),
          };
          await database.verification.create({ data: {
            id: randomUUID(), identifier: PREFIX[providerId] + digest(token),
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
          where: { identifier: { in: [PREFIX.google + digest(token), PREFIX.apple + digest(token)] }, expiresAt: { gt: new Date() } },
        });
        if (!row) throw invalid();
        const stored = JSON.parse(await symmetricDecrypt({ key: ctx.context.secretConfig, data: row.value })) as Continuation;
        if (stored.providerId === 'apple' && !configuredSocialProviderIds().includes('apple')) {
          scheduleSweep(ctx.context.secretConfig);
          throw invalid();
        }
        if (stored.bindingHash !== digest(binding)
          || (stored.nativeQueryHash && (typeof ctx.query?.oauthQuery !== 'string'
            || digest(ctx.query.oauthQuery) !== stored.nativeQueryHash))) throw invalid();
        return ctx.json({
          outcome: stored.outcome, providerId: stored.providerId,
          email: stored.profile.email, name: stored.profile.name,
          ...(stored.providerId === 'apple' ? { isPrivateEmail: stored.profile.isPrivateEmail } : {}),
        });
      }),
      socialConfirm: createAuthEndpoint('/social/confirm', { method: 'POST' }, async (ctx) => {
        ctx.setHeader('Referrer-Policy', 'no-referrer');
        const body = (ctx.body ?? {}) as { continuation?: unknown; oauthQuery?: unknown };
        const token = body.continuation;
        const binding = ctx.getCookie(COOKIE);
        if (typeof token !== 'string' || !binding) throw invalid();
        const row = await database.verification.findFirst({
          where: { identifier: { in: [PREFIX.google + digest(token), PREFIX.apple + digest(token)] }, expiresAt: { gt: new Date() } },
        });
        if (!row) throw invalid();
        const stored = JSON.parse(await symmetricDecrypt({ key: ctx.context.secretConfig, data: row.value })) as Continuation;
        if (stored.providerId === 'apple' && !configuredSocialProviderIds().includes('apple')) {
          scheduleSweep(ctx.context.secretConfig);
          throw invalid();
        }
        if ((stored.providerId !== 'apple' && stored.providerId !== 'google')
          || !row.identifier.startsWith(PREFIX[stored.providerId])
          || typeof stored.profile?.id !== 'string' || typeof stored.profile.email !== 'string'
          || !stored.profile.email || (stored.providerId === 'apple' && !stored.profile.clientId)
          || stored.bindingHash !== digest(binding) || stored.outcome !== 'new_account' || !stored.tokens
          || (stored.nativeQueryHash && (typeof body.oauthQuery !== 'string'
            || digest(body.oauthQuery) !== stored.nativeQueryHash))) throw invalid();
        const isApple = stored.providerId === 'apple';
        // Retire Apple's spendable continuation atomically, but keep its encrypted
        // tokens until Create succeeds or revocation succeeds. A crash leaves a
        // non-redeemable row for the expiry sweeper.
        const consumed = isApple
          ? await database.verification.updateMany({
            where: { id: row.id, value: row.value, identifier: row.identifier, expiresAt: { gt: new Date() } },
            data: { identifier: `${PREFIX.apple}revoke:${digest(token)}`, expiresAt: new Date(Date.now() + TTL_MS) },
          })
          : await database.verification.deleteMany({
            where: { id: row.id, value: row.value, expiresAt: { gt: new Date() } },
          });
        if (consumed.count !== 1) throw invalid();
        ctx.setCookie(COOKIE, '', { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0 });
        const { profile, tokens } = stored;
        const abandon = async () => {
          const linkedApple = isApple && await database.account.findFirst({
            where: { providerId: 'apple', accountId: profile.id }, select: { id: true },
          });
          if (linkedApple || await revokeAbandoned(stored)) {
            if (isApple) await database.verification.deleteMany({ where: { id: row.id } });
          } else {
            log('warn', 'auth_social_token_revoke_failed');
            if (isApple) await database.verification.updateMany({
              where: { id: row.id }, data: { expiresAt: new Date() },
            });
          }
        };
        if (await hasMatchingUser(database, profile.email)) {
          await abandon();
          throw new APIError('BAD_REQUEST', { code: 'ACCOUNT_ALREADY_EXISTS', message: 'Sign in to your existing OpenKey account.' });
        }
        let created;
        try {
          if (isApple) {
            await confirmedSocialProvider.set('apple');
            await appleTokenClientId.set(profile.clientId!);
          }
          created = await ctx.context.internalAdapter.createOAuthUser({
            email: profile.email, emailVerified: true, name: profile.name, image: profile.image,
          }, {
            providerId: stored.providerId, accountId: profile.id,
            accessToken: tokens.accessToken && await symmetricEncrypt({ key: ctx.context.secretConfig, data: tokens.accessToken }),
            refreshToken: tokens.refreshToken && await symmetricEncrypt({ key: ctx.context.secretConfig, data: tokens.refreshToken }),
            idToken: tokens.idToken,
            accessTokenExpiresAt: tokens.accessTokenExpiresAt ? new Date(tokens.accessTokenExpiresAt) : undefined,
            refreshTokenExpiresAt: tokens.refreshTokenExpiresAt ? new Date(tokens.refreshTokenExpiresAt) : undefined,
            scope: tokens.scope,
          });
        } catch (error) {
          if (await hasMatchingUser(database, profile.email)) {
            await abandon();
            throw new APIError('BAD_REQUEST', { code: 'ACCOUNT_ALREADY_EXISTS', message: 'Sign in to your existing OpenKey account.' });
          }
          if (await database.account.findFirst({
            where: { providerId: stored.providerId, accountId: profile.id }, select: { id: true },
          })) {
            await abandon();
            throw new APIError('BAD_REQUEST', { code: 'ACCOUNT_ALREADY_LINKED', message: 'This social identity is already linked.' });
          }
          await abandon();
          throw error;
        }
        if (isApple) await database.verification.deleteMany({ where: { id: row.id } });
        const session = await ctx.context.internalAdapter.createSession(created.user.id);
        await setSessionCookie(ctx, { session, user: created.user });
        if (isApple) await sendSocialAccountNotice(profile.email);
        log('info', 'auth_social_signup_confirmed');
        return ctx.json({ token: session.token, user: parseUserOutput(ctx.context.options, created.user) });
      }),
    },
  } satisfies BetterAuthPlugin;
}
