// Operator stop-all for renewal leases (TC-3088). Dry run by default; counts only.
//
//   POST /api/internal/renewal-leases/stop-all                      -> counts what a run would stop
//   POST /api/internal/renewal-leases/stop-all  {"apply": true}     -> stops every live lease an OpenKey-held key signed
//
// Both need `Authorization: Bearer $OPENKEY_RENEWAL_STOP_TOKEN` (a token for this route only, not the metrics token or
// any admin secret) and an `X-Operator` label for the audit line. Without the token configured the route refuses (503);
// with a wrong or missing token it answers 401. The stop is the same `revokeRenewalLeases` that Settings "Stop renewal",
// sign-out and account deletion use, one account at a time; a lease an external wallet signed is skipped and counted.
import { timingSafeEqual } from 'node:crypto';
import { Hono } from 'hono';
import { logRenewalLeaseStopAll } from '../log';
import { renewalLeaseReport, type RenewalLeaseReportDatabase } from '../services/renewal-lease-report';
import { stopAllRenewalLeasesOnce, type RenewalLeaseSweepDatabase } from '../services/renewal-lease-sweep';
import type { LeaseRevocationDeps } from '../services/renewal-lease-revocation';

export type InternalRenewalLeaseDatabase = RenewalLeaseSweepDatabase & RenewalLeaseReportDatabase;

const OPERATOR_LABEL = /^[A-Za-z0-9_.@-]{1,64}$/;

function authorized(header: string | undefined, token: string): boolean {
  if (!header?.startsWith('Bearer ')) return false;
  const provided = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}

export function createInternalRenewalLeaseRouter(db: InternalRenewalLeaseDatabase, deps?: LeaseRevocationDeps) {
  const router = new Hono();

  router.post('/stop-all', async (c) => {
    c.header('Cache-Control', 'no-store');
    const token = process.env.OPENKEY_RENEWAL_STOP_TOKEN;
    if (!token) return c.json({ error: 'Renewal stop-all is not configured' }, 503);
    if (!authorized(c.req.header('authorization'), token)) return c.json({ error: 'Unauthorized' }, 401);
    const operator = c.req.header('x-operator') ?? '';
    if (!OPERATOR_LABEL.test(operator)) return c.json({ error: 'X-Operator must be a short label of letters, digits and . _ @ -' }, 400);
    const body = await c.req.json().catch(() => ({})) as { apply?: unknown };
    if (body.apply !== undefined && typeof body.apply !== 'boolean') return c.json({ error: 'apply must be true or false' }, 400);
    const apply = body.apply === true;

    // What is live now, split by who signed it: the dry run, and the "would stop" count of an applied run.
    const before = await renewalLeaseReport(db);
    if (!apply) {
      logRenewalLeaseStopAll({ operator, apply, wouldStop: before.openkeySigned, stopped: 0, failed: 0, skippedExternal: before.walletSigned });
      return c.json({ mode: 'dry-run', wouldStop: before.openkeySigned, skippedExternal: before.walletSigned });
    }
    const result = await stopAllRenewalLeasesOnce(db, deps);
    const counts = { stopped: result.stopped, failed: result.notStopped, skippedExternal: result.walletRequired };
    logRenewalLeaseStopAll({ operator, apply, wouldStop: before.openkeySigned, ...counts });
    return c.json({ mode: 'applied', wouldStop: before.openkeySigned, ...counts });
  });

  return router;
}
