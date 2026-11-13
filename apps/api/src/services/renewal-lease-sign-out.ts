// Signing out stops renewal (TC-2946). Before a sign-out removes sessions, the renewal leases approved
// under those sessions are revoked at their nodes: signing out of this session stops the leases it
// approved, signing out of other sessions stops every lease but this session's, and signing out
// everywhere stops them all. Stopping leases never blocks or fails a sign-out: any error while stopping
// them leaves those leases on (unsettled, so the next stop, sign-out or deletion retries them) and the
// sign-out goes ahead. Its answer gains `renewalLeases`, which counts only the leases a node settled as
// stopped; a lease left on stays listed in Settings.
import type { BetterAuthPlugin } from 'better-auth';
import { createAuthMiddleware, getSessionFromCtx } from 'better-auth/api';
import { defineRequestState } from '@better-auth/core/context';
import type { PrismaClient } from '@openkey/db';
import { liveLeaseWhere, revokeRenewalLeases, type LeaseRevocationReport, type LeaseScope } from './renewal-lease-revocation';

const SIGN_OUT_PATHS = new Set(['/sign-out', '/revoke-session', '/revoke-sessions', '/revoke-other-sessions']);

const signOutLeaseReport = defineRequestState<LeaseRevocationReport | undefined>(() => undefined);

export function renewalLeaseSignOutPlugin(database: PrismaClient, revoke = revokeRenewalLeases) {
  return {
    id: 'openkey-renewal-lease-sign-out',
    hooks: {
      before: [{
        matcher: (ctx) => SIGN_OUT_PATHS.has(ctx.path ?? ''),
        handler: createAuthMiddleware(async (ctx) => {
          let userId: string | undefined;
          let scope: LeaseScope | undefined;
          try {
            // The same session check the revoke endpoints make; without a session nothing is signed out.
            const current = await getSessionFromCtx(ctx, { disableCookieCache: true });
            if (!current?.session) return;
            userId = current.user.id;
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
          } catch {
            // Never fail the sign-out: report the leases still on, if they can be read, and let it go ahead.
            if (!userId || !scope) return;
            const left = await database.renewalLease.findMany({ where: liveLeaseWhere(userId, scope, new Date()), select: { leaseCid: true } })
              .catch(() => []);
            await signOutLeaseReport.set({ stopped: [], notStopped: left.map(({ leaseCid }) => ({ leaseCid, reason: 'node_unavailable' as const })) });
          }
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
