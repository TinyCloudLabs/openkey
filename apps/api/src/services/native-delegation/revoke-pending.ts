import { randomBytes } from 'node:crypto';
import { ensureEip55, siweToDelegationHeaders } from '@tinycloud/node-sdk-wasm';
import { buildOwnerRevocationSiwe } from '@openkey/capability-review';
import { Prisma, type PrismaClient } from '@openkey/db';
import { log, logError, logMetric, withScheduledLogContext } from '../../log';
import { isKnownTinyCloudActivationHost } from '../tinycloud-hosts';
import { signManagedKey } from '../managed-key-signing';
import { primaryKeyWhere } from '../primary-key';
import { enabledNativeDelegation } from './policy';

/**
 * Delegations a step-up approval put on a node but that OpenKey then withdrew (TC-3569). The request row keeps
 * this record, never the delegation itself: an identifier and where to send the revocation, no signature and no
 * header. A sweep retries it until the node confirms the revoke or the delegation expires on its own.
 */
export type RevokePendingRecord = {
  revokePending: true;
  delegationCid: string;
  tinycloudHost: string;
  address: string;
  grantId: string;
  appId: string;
  expiresAt: string;
  siweDomain: string;
};
export function revokePendingRecord(
  artifact: { delegationCid: string; tinycloudHost: string; address: string; grantId: string; appId: string; expiresAt: string },
  siweDomain: string,
): RevokePendingRecord {
  return { revokePending: true, delegationCid: artifact.delegationCid, tinycloudHost: artifact.tinycloudHost, address: artifact.address,
    grantId: artifact.grantId, appId: artifact.appId, expiresAt: artifact.expiresAt, siweDomain };
}

export function isRevokePendingRecord(value: unknown): value is RevokePendingRecord {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return record.revokePending === true && ['delegationCid', 'tinycloudHost', 'address', 'grantId', 'appId', 'expiresAt', 'siweDomain']
    .every((key) => typeof record[key] === 'string' && (record[key] as string).length > 0);
}

/** The record for an approved request's stored delegation artifact, or `null` when the artifact is not one. */
export function revokePendingRecordFor(artifact: unknown, siweDomain: string): RevokePendingRecord | null {
  const record = typeof artifact === 'object' && artifact !== null ? artifact as Record<string, unknown> : null;
  if (!record) return null;
  const candidate = { revokePending: true, delegationCid: record.delegationCid, tinycloudHost: record.tinycloudHost, address: record.address,
    grantId: record.grantId, appId: record.appId, expiresAt: record.expiresAt, siweDomain };
  return isRevokePendingRecord(candidate) ? candidate : null;
}

export interface OwnerRevocationHost {
  revokeDelegation: (host: string, headers: Record<string, string>) => Promise<{ ok: boolean; status: number }>;
}

export async function revokeDelegationOnNode(host: string, headers: Record<string, string>): Promise<{ ok: boolean; status: number }> {
  const response = await fetch(`${host}/revoke`, { method: 'POST', headers, signal: AbortSignal.timeout(5_000) });
  return { ok: response.ok, status: response.status };
}

/** The log events a failed owner revocation may be reported under: the caller says which flow it is. */
export type OwnerRevocationFailureEvent = 'native_consent_stale_session_revoke_failed' | 'native_stepup_revoke_pending_refused';

/** Asks the node to revoke one delegation with the owner's signature. Never throws; `true` only on the node's own OK. */
export async function revokeOwnerDelegation(
  artifact: { address: string; delegationCid: string; tinycloudHost: string },
  domain: string,
  sign: (message: string) => Promise<string>,
  host: OwnerRevocationHost,
  failureEvent: OwnerRevocationFailureEvent = 'native_consent_stale_session_revoke_failed',
): Promise<boolean> {
  try {
    const now = new Date();
    const address = ensureEip55(artifact.address);
    const siwe = buildOwnerRevocationSiwe({ kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${address}`, cid: artifact.delegationCid,
      nonce: randomBytes(16).toString('hex'), expiresAt: new Date(now.getTime() + 600_000).toISOString() }, domain, now);
    const signature = await sign(siwe);
    const response = await host.revokeDelegation(artifact.tinycloudHost, siweToDelegationHeaders({ siwe, signature }) as Record<string, string>);
    if (!response.ok) logMetric('warn', failureEvent, { status: response.status });
    return response.ok;
  } catch { log('warn', failureEvent); return false; }
}

export type RevokePendingDatabase = Pick<PrismaClient, 'tinyCloudNativeRequest' | 'tinyCloudNativeStepUpDelegation' | 'ethereumKey' | 'user'>;

export interface RevokePendingDeps {
  host: OwnerRevocationHost;
  signManaged: typeof signManagedKey;
  now: () => Date;
}

const defaultDeps: RevokePendingDeps = { host: { revokeDelegation: revokeDelegationOnNode }, signManaged: signManagedKey, now: () => new Date() };

export const REVOKE_PENDING_SWEEP_INTERVAL_MS = 60_000;
const FIRST_PASS_DELAY_MS = 20_000;
const PASS_LIMIT = 200;

export interface RevokePendingReport {
  /** Records still waiting after the pass. */
  pending: number;
  revoked: number;
  /** Records whose delegation ended by itself: dropped without a node call. */
  expired: number;
}

/**
 * Approved step-up requests whose delegation is live on the node but that can no longer be redeemed: their consent
 * was withdrawn (`WITHDRAWN`), or their grant was revoked by sign-out, an Apple revoke or a direct SQL revoke
 * (`APPROVED` on a `REVOKED` grant). Each is turned into a `revokePending` record in one conditional UPDATE, which
 * also drops the signature and the delegation header the row would otherwise keep. A request that gets redeemed
 * first no longer matches and is left alone. Covers every path in one place, so no revoke path has to remember it.
 */
async function recordUnredeemableApprovals(db: RevokePendingDatabase): Promise<void> {
  const rows = await db.tinyCloudNativeRequest.findMany({
    where: { kind: 'STEPUP', hosting: 'existing', signature: { not: null }, OR: [{ status: 'WITHDRAWN' }, { status: 'APPROVED', grant: { is: { status: 'REVOKED' } } }] },
    include: { client: true },
    orderBy: { updatedAt: 'asc' },
    take: PASS_LIMIT,
  });
  for (const row of rows) {
    const siweDomain = enabledNativeDelegation(row.client)?.siweDomain ?? 'openkey.so';
    const record = revokePendingRecordFor(row.delegation, siweDomain);
    await db.tinyCloudNativeRequest.updateMany({
      where: { id: row.id, kind: 'STEPUP', signature: { not: null }, OR: [{ status: 'WITHDRAWN' }, { status: 'APPROVED', grant: { is: { status: 'REVOKED' } } }] },
      data: { ...(row.status === 'APPROVED' ? { status: 'DENIED' } : {}), hosting: 'failed', signature: null, delegation: record ?? Prisma.DbNull },
    });
  }
}

/**
 * One pass over everything waiting to be revoked on a node:
 * - approved step-up requests that can no longer be redeemed (see `recordUnredeemableApprovals`);
 * - every request row that holds a `revokePending` record, whatever its status (a withdrawn consent leaves its
 *   requests `WITHDRAWN`; the delegation they put on the node is still live);
 * - every step-up delegation the database marked when its step-up was revoked (`revokeRequestedAt`).
 * An entry is cleared only after the node answers OK, or once the delegation has expired by itself, or when it can
 * never be revoked (no owner, or not a record). One that is gated or that the node refuses stays, and moves to the
 * back of the queue (`updatedAt` / `lastAttemptAt`), so entries that keep failing cannot starve the rest.
 */
export async function sweepRevokePendingOnce(db: RevokePendingDatabase, deps: RevokePendingDeps = defaultDeps): Promise<RevokePendingReport> {
  const report: RevokePendingReport = { pending: 0, revoked: 0, expired: 0 };
  // Delegations nobody asked to revoke that have run out: nothing is left on the node, so nothing is left to keep.
  await db.tinyCloudNativeStepUpDelegation.deleteMany({ where: { expiresAt: { lte: deps.now() }, revokeRequestedAt: null } });
  await recordUnredeemableApprovals(db);

  const attempt = async (
    userId: string | null,
    record: { address: string; delegationCid: string; tinycloudHost: string; siweDomain: string; expiresAt: string },
    clear: () => Promise<unknown>,
    later: () => Promise<unknown>,
  ) => {
    if (!userId) { await clear(); report.expired += 1; return; }
    if (Date.parse(record.expiresAt) <= deps.now().getTime()) { await clear(); report.expired += 1; return; }
    const wait = async () => { report.pending += 1; await later(); };
    // The server signs unattended here, so it is as strict as every other signing path: a node OpenKey may talk to,
    // and never for an account that took its key back (USER_CONTROLLED_EXCLUSIVE). Both leave the entry to expire.
    if (!isKnownTinyCloudActivationHost(record.tinycloudHost)) { await wait(); return; }
    try {
      const account = await db.user.findUnique({ where: { id: userId }, select: { tinyCloudManageKeyMode: true } });
      if (!account || account.tinyCloudManageKeyMode === 'USER_CONTROLLED_EXCLUSIVE') { await wait(); return; }
      const key = await db.ethereumKey.findFirst({ where: primaryKeyWhere(userId) });
      // The delegation was signed by the owner address it names; only that key can revoke it.
      if (!key?.sealedBlob || ensureEip55(key.address) !== ensureEip55(record.address)) { await wait(); return; }
      const revoked = await revokeOwnerDelegation(record, record.siweDomain,
        (message) => deps.signManaged({ userId: key.userId, sealingContext: key.sealingContext }, key.sealedBlob!, message), deps.host,
        'native_stepup_revoke_pending_refused');
      if (revoked) { await clear(); report.revoked += 1; } else await wait();
    } catch (error) {
      logError('warn', 'native_stepup_revoke_pending_failed', error);
      await wait();
    }
  };

  const requests = await db.tinyCloudNativeRequest.findMany({
    where: { kind: 'STEPUP', delegation: { path: ['revokePending'], equals: true } },
    select: { id: true, userId: true, delegation: true },
    orderBy: { updatedAt: 'asc' },
    take: PASS_LIMIT,
  });
  for (const row of requests) {
    const record = row.delegation;
    const clear = () => db.tinyCloudNativeRequest.updateMany({ where: { id: row.id }, data: { delegation: Prisma.DbNull } });
    // Not a usable record: nothing can ever be revoked from it, and keeping it would hold a place in every pass.
    if (!isRevokePendingRecord(record)) { await clear(); report.expired += 1; continue; }
    // Rewriting the record bumps `updatedAt`, which is the queue order.
    await attempt(row.userId, record, clear,
      () => db.tinyCloudNativeRequest.updateMany({ where: { id: row.id }, data: { delegation: record } }));
  }

  const delegations = await db.tinyCloudNativeStepUpDelegation.findMany({
    where: { revokeRequestedAt: { not: null } },
    select: { id: true, address: true, delegationCid: true, tinycloudHost: true, siweDomain: true, expiresAt: true, stepUp: { select: { grant: { select: { userId: true } } } } },
    orderBy: [{ lastAttemptAt: { sort: 'asc', nulls: 'first' } }, { revokeRequestedAt: 'asc' }],
    take: PASS_LIMIT,
  });
  for (const row of delegations) {
    await attempt(row.stepUp.grant.userId, { ...row, expiresAt: row.expiresAt.toISOString() },
      () => db.tinyCloudNativeStepUpDelegation.deleteMany({ where: { id: row.id } }),
      () => db.tinyCloudNativeStepUpDelegation.updateMany({ where: { id: row.id }, data: { lastAttemptAt: deps.now() } }));
  }
  return report;
}

let timer: ReturnType<typeof setInterval> | undefined;
let first: ReturnType<typeof setTimeout> | undefined;

/** Starts the in-process sweep. Idempotent: a second call returns the same stop function. */
export function startRevokePendingSweep(db: RevokePendingDatabase, deps?: RevokePendingDeps): () => void {
  if (!timer) {
    let running = false;
    const pass = () => {
      if (running) return;
      running = true;
      void sweepRevokePendingOnce(db, deps)
        .then((report) => withScheduledLogContext(() => {
          if (report.revoked + report.expired + report.pending > 0) {
            logMetric(report.pending > 0 ? 'warn' : 'info', 'native_stepup_revoke_pending', { count: report.pending });
          }
        }))
        .catch((error) => withScheduledLogContext(() => logError('error', 'native_stepup_revoke_pending_sweep_failed', error)))
        .finally(() => { running = false; });
    };
    timer = setInterval(pass, REVOKE_PENDING_SWEEP_INTERVAL_MS);
    timer.unref();
    first = setTimeout(pass, FIRST_PASS_DELAY_MS);
    first.unref();
  }
  return () => { clearInterval(timer); clearTimeout(first); timer = undefined; first = undefined; };
}
