// Signing out stops renewal (TC-2946). Before a sign-out removes sessions, the renewal leases approved
// under those sessions are revoked at their nodes: signing out of this session stops the leases it
// approved, signing out of other sessions stops every lease but this session's, and signing out
// everywhere stops them all. Sign-out itself always goes ahead; its answer gains `renewalLeases`,
// which counts only the leases a node confirmed as stopped. A lease left on stays listed in Settings.
import type { BetterAuthPlugin } from 'better-auth';
import { createAuthMiddleware, getSessionFromCtx } from 'better-auth/api';
import { defineRequestState } from '@better-auth/core/context';
import type { PrismaClient } from '@openkey/db';
import { revokeRenewalLeases, type LeaseRevocationReport, type LeaseScope } from './renewal-lease-revocation';

const SIGN_OUT_PATHS = new Set(['/sign-out', '/revoke-session', '/revoke-sessions', '/revoke-other-sessions']);

const signOutLeaseReport = defineRequestState<LeaseRevocationReport | undefined>(() => undefined);

export function renewalLeaseSignOutPlugin(database: PrismaClient, revoke = revokeRenewalLeases) {
  return {
    id: 'openkey-renewal-lease-sign-out',
    hooks: {
      before: [{
        matcher: (ctx) => SIGN_OUT_PATHS.has(ctx.path ?? ''),
        handler: createAuthMiddleware(async (ctx) => {
          // The same session check the revoke endpoints make; without a session nothing is signed out.
          const current = await getSessionFromCtx(ctx, { disableCookieCache: true });
          if (!current?.session) return;
          const userId = current.user.id;
          let scope: LeaseScope;
          if (ctx.path === '/sign-out') scope = { kind: 'session', sessionId: current.session.id };
          else if (ctx.path === '/revoke-sessions') scope = { kind: 'all' };
          else if (ctx.path === '/revoke-other-sessions') scope = { kind: 'other-sessions', keepSessionId: current.session.id };
          else {
            const token = (ctx.body as { token?: unknown } | undefined)?.token;
            if (typeof token !== 'string') return;
            const target = await database.session.findFirst({ where: { token, userId }, select: { id: true } });
            if (!target) return;
            scope = { kind: 'session', sessionId: target.id };
          }
          await signOutLeaseReport.set(await revoke(database, userId, scope));
        }),
      }],
      after: [{
        matcher: (ctx) => SIGN_OUT_PATHS.has(ctx.path ?? ''),
        handler: createAuthMiddleware(async (ctx) => {
          const report = await signOutLeaseReport.get();
          const returned = ctx.context.returned;
          // A sign-out with no lease in scope answers exactly as before.
          if (!report || report.stopped.length + report.notStopped.length === 0) return;
          if (!returned || typeof returned !== 'object' || returned instanceof Response || returned instanceof Error) return;
          const walletRequired = report.notStopped.filter((lease) => lease.reason === 'wallet_required').length;
          return ctx.json({
            ...returned,
            renewalLeases: { stopped: report.stopped.length, notStopped: report.notStopped.length, walletRequired },
          });
        }),
      }],
    },
  } satisfies BetterAuthPlugin;
}
