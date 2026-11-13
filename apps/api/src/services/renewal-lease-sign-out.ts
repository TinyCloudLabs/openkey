// Signing out stops renewal (TC-2946). The sign-out itself always comes first and is never held up or failed by
// renewal: once the sessions have ended, the renewal leases approved under them are revoked at their nodes, best
// effort. Signing out of this session stops the leases it approved, signing out of other sessions stops every lease
// but this session's, and signing out everywhere stops them all. Stopping them never waits for the owner's user lock:
// while another request (an account deletion, another stop) holds it, or on any error, those leases stay on,
// unsettled, so the next stop, sign-out or deletion retries them. The answer gains `renewalLeases`, which counts only
// the leases a node settled as stopped; a lease left on stays listed in Settings.
import type { BetterAuthPlugin } from 'better-auth';
import { createAuthMiddleware, getSessionFromCtx } from 'better-auth/api';
import { defineRequestState } from '@better-auth/core/context';
import type { PrismaClient } from '@openkey/db';
import { liveLeaseWhere, revokeRenewalLeases, type LeaseRevocationReport, type LeaseScope } from './renewal-lease-revocation';

const SIGN_OUT_PATHS = new Set(['/sign-out', '/revoke-session', '/revoke-sessions', '/revoke-other-sessions']);

/** Whose leases this sign-out covers, read before its sessions end. */
const signOutLeaseScope = defineRequestState<{ userId: string; scope: LeaseScope } | undefined>(() => undefined);

export function renewalLeaseSignOutPlugin(database: PrismaClient, revoke = revokeRenewalLeases) {
  /** Stops the leases best effort, without waiting for the owner's lock; never throws. */
  async function stopLeases(userId: string, scope: LeaseScope): Promise<LeaseRevocationReport> {
    try {
      return await revoke(database, userId, scope, undefined, { waitForLock: false });
    } catch {
      const left = await database.renewalLease.findMany({ where: liveLeaseWhere(userId, scope, new Date()), select: { leaseCid: true } })
        .catch(() => []);
      return { stopped: [], notStopped: left.map(({ leaseCid }) => ({ leaseCid, reason: 'node_unavailable' as const })) };
    }
  }

  return {
    id: 'openkey-renewal-lease-sign-out',
    hooks: {
      before: [{
        matcher: (ctx) => SIGN_OUT_PATHS.has(ctx.path ?? ''),
        handler: createAuthMiddleware(async (ctx) => {
          try {
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
            await signOutLeaseScope.set({ userId, scope });
          } catch {
            // Reading the scope never fails the sign-out; its leases then simply stay on.
          }
        }),
      }],
      after: [{
        matcher: (ctx) => SIGN_OUT_PATHS.has(ctx.path ?? ''),
        handler: createAuthMiddleware(async (ctx) => {
          const covered = await signOutLeaseScope.get();
          const returned = ctx.context.returned;
          // Only after a sign-out that succeeded: its sessions have already ended.
          if (!covered || !returned || typeof returned !== 'object' || returned instanceof Response || returned instanceof Error) return;
          const report = await stopLeases(covered.userId, covered.scope);
          // A sign-out with no lease in scope answers exactly as before.
          if (report.stopped.length + report.notStopped.length === 0) return;
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
