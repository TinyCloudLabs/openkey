import { createHash, randomUUID } from 'node:crypto';
import type { BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthMiddleware } from 'better-auth/api';
import { defineRequestState } from '@better-auth/core/context';
import type { PrismaClient } from '@openkey/db';
import type { SocialProviderId } from '../social-providers';
import { hasFreshEmailStepUp } from './email-otp-step-up';

const PREFIX = 'openkey-social-oauth-state:';
const TTL_MS = 10 * 60 * 1000;
type LinkSession = { sessionId: string; userId: string; providerId: SocialProviderId };
type Binding = { kind: 'sign-in' } | ({ kind: 'link' } & LinkSession);

const committingSocialLink = defineRequestState<LinkSession | undefined>(() => undefined);

function digest(state: string): string {
  return createHash('sha256').update(state).digest('base64url');
}
function invalidLink(): APIError {
  return new APIError('FORBIDDEN', {
    code: 'EMAIL_STEP_UP_REQUIRED',
    message: 'Verify an email code in the current session before linking an account.',
  });
}

export async function assertCurrentSocialLink(database: PrismaClient, providerId?: SocialProviderId, userId?: string): Promise<void> {
  const binding = await committingSocialLink.get();
  if (!binding) return;
  if (providerId && binding.providerId !== providerId) throw invalidLink();
  const session = await database.session.findUnique({
    where: { id: binding.sessionId }, select: { userId: true, expiresAt: true },
  });
  if ((userId && binding.userId !== userId) || session?.userId !== binding.userId || session.expiresAt <= new Date()
    || !await hasFreshEmailStepUp(database, binding.sessionId)) throw invalidLink();
}

export function socialLinkStatePlugin(database: PrismaClient) {
  let lastSweepAt = 0;
  return {
    id: 'openkey-social-link-state',
    hooks: {
      // Register both sign-in and link states so an unregistered state cannot
      // be mistaken for an older, unbound link at callback.
      after: [{
        matcher: (ctx) => ctx.path === '/link-social' || ctx.path === '/sign-in/social',
        handler: createAuthMiddleware(async (ctx) => {
          const providerId = (ctx.body as { provider?: string } | undefined)?.provider;
          if (providerId !== 'google' && providerId !== 'apple') return;
          const url = (ctx.context.returned as { url?: string } | undefined)?.url;
          if (!url) return;
          const state = new URL(url).searchParams.get('state');
          if (!state) return;
          const now = Date.now();
          if (now - lastSweepAt >= TTL_MS) {
            await database.verification.deleteMany({
              where: { identifier: { startsWith: PREFIX }, expiresAt: { lte: new Date(now) } },
            });
            lastSweepAt = now;
          }
          const current = ctx.context.session;
          if (ctx.path === '/link-social' && (!current?.session || !current.user)) throw invalidLink();
          const binding: Binding = ctx.path === '/link-social'
            ? { kind: 'link', sessionId: current!.session.id, userId: current!.user.id, providerId }
            : { kind: 'sign-in' };
          await database.verification.create({ data: {
            id: randomUUID(), identifier: PREFIX + providerId + ':' + digest(state), value: JSON.stringify(binding),
            expiresAt: new Date(Date.now() + TTL_MS),
          } });
        }),
      }],
      // BA's link state contains a user ID, not the originating session. A
      // revoked or stale session must never authorize the later Account write.
      before: [{
        matcher: (ctx) => ctx.path === '/callback/:id',
        handler: createAuthMiddleware(async (ctx) => {
          const providerId = ctx.params?.id;
          if (providerId !== 'google' && providerId !== 'apple') return;
          // Apple's form_post first redirects to GET; BA parses state only on GET.
          if (ctx.method !== 'GET') return;
          const state = ctx.query?.state;
          if (typeof state !== 'string') throw invalidLink();
          const row = await database.verification.findFirst({
            where: { identifier: PREFIX + providerId + ':' + digest(state), expiresAt: { gt: new Date() } },
          });
          if (!row) throw invalidLink();
          const binding = JSON.parse(row.value) as Binding;
          if (binding.kind === 'link') {
            await committingSocialLink.set({ sessionId: binding.sessionId, userId: binding.userId, providerId });
            await assertCurrentSocialLink(database, providerId, binding.userId);
          }
          const consumed = await database.verification.deleteMany({
            where: { id: row.id, value: row.value, expiresAt: { gt: new Date() } },
          });
          if (consumed.count !== 1) throw invalidLink();
        }),
      }],
    },
  } satisfies BetterAuthPlugin;
}
