// The owner's renewal leases on the dashboard (TC-2946): list them, and stop one by its exact lease CID.
// Mounted under /api/account, so every route already has a signed-in session from an OpenKey origin.
import { Hono } from 'hono';
import type { PrismaClient } from '@openkey/db';
import type { SessionContext } from '../middleware/session';
import { rejectNonBrowserControlRequest } from '../middleware/browser-control';
import {
  LeaseRevocationError,
  leaseRevocationSiwe,
  liveLeaseWhere,
  revokeLeaseWithWalletSignature,
  revokeRenewalLeases,
  type LeaseRevocationDeps,
} from '../services/renewal-lease-revocation';

export type RenewalLeaseRouteDatabase = Pick<PrismaClient, 'renewalLease' | 'ethereumKey' | 'approvalRequest' | '$transaction'>;

/** The approved request's reason, which the approval screen showed; the permissions come from the signed grant itself. */
function requestReason(request: unknown): string | null {
  return request && typeof request === 'object' && 'reason' in request && typeof request.reason === 'string' ? request.reason : null;
}

export function createRenewalLeaseRouter(db: RenewalLeaseRouteDatabase, deps?: LeaseRevocationDeps) {
  const router = new Hono<SessionContext>();
  const now = () => deps?.now() ?? new Date();

  // The account's leases that still renew: not stopped and not past their end.
  router.get('/', async (c) => {
    const userId = c.get('user').id;
    const leases = await db.renewalLease.findMany({ where: liveLeaseWhere(userId, { kind: 'all' }, now()), orderBy: { approvedAt: 'desc' } });
    const [requests, keys] = await Promise.all([
      db.approvalRequest.findMany({ where: { id: { in: leases.map((lease) => lease.approvalRequestId) } }, select: { id: true, request: true, delegationExpiresAt: true } }),
      db.ethereumKey.findMany({ where: { userId }, select: { address: true, keyType: true } }),
    ]);
    c.header('Cache-Control', 'no-store');
    return c.json({
      leases: leases.map((lease) => {
        const owner = lease.ownerDid.split(':').at(-1)?.toLowerCase();
        const key = keys.find((candidate) => candidate.address.toLowerCase() === owner);
        const request = requests.find((row) => row.id === lease.approvalRequestId);
        return {
          leaseCid: lease.leaseCid,
          originalCid: lease.originalCid,
          nodeOrigin: lease.nodeOrigin,
          approvedAt: lease.approvedAt.toISOString(),
          leaseExpiresAt: lease.leaseExpiresAt.toISOString(),
          // The grant's own signed end: once renewal stops, the grant ends there (the node drops renewed time).
          grantExpiresAt: request?.delegationExpiresAt?.toISOString() ?? null,
          // A wallet-signed lease is stopped by that wallet signing its revocation.
          signer: key?.keyType === 'MANAGED' ? 'openkey' : 'wallet',
          reason: requestReason(request?.request),
          grantSiwe: lease.grantSiwe,
        };
      }),
    });
  });

  // Stop one lease: revoke exactly this lease at its node. A lease OpenKey's key signed is revoked at once.
  // A wallet-signed lease answers 409 `wallet_required` with the message to sign; the same call with
  // `{ siwe, signature }` sends the wallet's revocation.
  router.post('/:leaseCid/stop', async (c) => {
    const rejected = rejectNonBrowserControlRequest(c);
    if (rejected) return rejected;
    const userId = c.get('user').id;
    const leaseCid = c.req.param('leaseCid');
    c.header('Cache-Control', 'no-store');
    const body = await c.req.json().catch(() => ({})) as { siwe?: unknown; signature?: unknown };
    if (body.siwe !== undefined || body.signature !== undefined) {
      if (typeof body.siwe !== 'string' || typeof body.signature !== 'string') return c.json({ error: 'Invalid wallet signature', code: 'invalid_signature' }, 400);
      try {
        await revokeLeaseWithWalletSignature(db, userId, { leaseCid, siwe: body.siwe, signature: body.signature }, deps);
      } catch (error) {
        if (error instanceof LeaseRevocationError) return c.json({ error: error.message, code: error.code }, error.status);
        throw error;
      }
      return c.json({ stopped: true });
    }
    const lease = await db.renewalLease.findFirst({ where: liveLeaseWhere(userId, { kind: 'lease', leaseCid }, now()) });
    // Another account's lease, an unknown one, and one already stopped or ended all read the same.
    if (!lease) return c.json({ error: 'Renewal not found', code: 'not_found' }, 404);
    const report = await revokeRenewalLeases(db, userId, { kind: 'lease', leaseCid }, deps);
    // A simultaneous stop of the same lease may have settled it first: that is still a stop.
    if (report.stopped.includes(leaseCid) || (report.notStopped.length === 0 && !await db.renewalLease.findFirst({ where: liveLeaseWhere(userId, { kind: 'lease', leaseCid }, now()) }))) {
      return c.json({ stopped: true });
    }
    if (report.notStopped[0]?.reason === 'wallet_required') {
      return c.json({ error: 'Sign with your wallet to stop this renewal', code: 'wallet_required', siwe: leaseRevocationSiwe(lease, now()) }, 409);
    }
    return c.json({ error: "Couldn't stop renewal, so it's still on. Try again.", code: 'node_unavailable' }, 503);
  });

  return router;
}
