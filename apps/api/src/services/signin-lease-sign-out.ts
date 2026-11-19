// An app signing out stops its own sign-in renewal. A sign-in lease renews the grant OpenKey signed for the app's
// session key when the app signed in through this OpenKey session; when that session signs itself out (the app's
// sign-out does exactly this), the app drops the key, so the lease would only renew a grant nobody holds. Only
// `/sign-out` counts, and only the sign-in leases recorded under the session it ends: a permission the owner
// approved keeps renewing, and ending other sessions (`/revoke-session`, `/revoke-other-sessions`,
// `/revoke-sessions`) stops nothing. The sign-out comes first and answers as before; the stop is best effort and
// never waits for the owner's lock. A lease it can't stop stays listed in Settings, where the owner can stop it.
import type { BetterAuthPlugin } from 'better-auth';
import { createAuthMiddleware, getSessionFromCtx } from 'better-auth/api';
import { defineRequestState } from '@better-auth/core/context';
import type { PrismaClient } from '@openkey/db';
import { revokeRenewalLeases, stopRenewalLeasesBestEffort } from './renewal-lease-revocation';

/** The session this sign-out ends, read before it ends. */
const signingOut = defineRequestState<{ userId: string; sessionId: string } | undefined>(() => undefined);

export function signInLeaseSignOutPlugin(database: PrismaClient, revoke = revokeRenewalLeases) {
  return {
    id: 'openkey-sign-in-lease-sign-out',
    hooks: {
      before: [{
        matcher: (ctx) => ctx.path === '/sign-out',
        handler: createAuthMiddleware(async (ctx) => {
          try {
            const current = await getSessionFromCtx(ctx, { disableCookieCache: true });
            if (current?.session) await signingOut.set({ userId: current.user.id, sessionId: current.session.id });
          } catch {
            // Reading the session never fails the sign-out; its sign-in lease then stays on.
          }
        }),
      }],
      after: [{
        matcher: (ctx) => ctx.path === '/sign-out',
        handler: createAuthMiddleware(async (ctx) => {
          const ended = await signingOut.get();
          const returned = ctx.context.returned;
          // Only after a sign-out that succeeded.
          if (!ended || !returned || typeof returned !== 'object' || returned instanceof Response || returned instanceof Error) return;
          await stopRenewalLeasesBestEffort(database, ended.userId, { kind: 'sign-in', sessionId: ended.sessionId }, revoke);
        }),
      }],
    },
  } satisfies BetterAuthPlugin;
}
