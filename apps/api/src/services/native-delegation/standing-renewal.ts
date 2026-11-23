import type { Prisma } from '@openkey/db';
import {
  MAX_LEASE_SECONDS,
  RenewalLeaseError,
  prepareRenewalStage,
  renewalLeasesEnabled,
  signLease,
  type ApprovalResultRenewal,
  type SignedRenewalRequest,
} from '../renewal-lease';
import { reserveRenewalLeaseInTransaction, reservedLeaseAuthorization } from '../renewal-lease-revocation';
import { isKnownTinyCloudActivationHost } from '../tinycloud-hosts';

export type NativeRenewalAsk = SignedRenewalRequest & { purpose?: 'standing' | 'task' };
export const NATIVE_LEASED_WINDOW_SECONDS = 24 * 60 * 60;

export function nativeRenewalHostAllowed(host: string): boolean {
  return isKnownTinyCloudActivationHost(host) && new URL(host).origin === host;
}

export function bindNativeRenewalAsk(value: unknown, host: string): NativeRenewalAsk | undefined {
  if (!renewalLeasesEnabled() || value === undefined) return undefined;
  const ask = value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
  const seconds = ask?.leaseLifetimeSeconds;
  const purpose = ask?.purpose;
  if (!ask || ask.version !== 1 || Object.keys(ask).some(key => !['version', 'leaseLifetimeSeconds', 'purpose'].includes(key)) ||
      typeof seconds !== 'number' || !Number.isSafeInteger(seconds) || seconds < 1 || seconds > MAX_LEASE_SECONDS ||
      (purpose !== undefined && purpose !== 'standing' && purpose !== 'task')) {
    throw new RenewalLeaseError('invalid_renewal_request', 'renewal must be { version: 1, leaseLifetimeSeconds } with at most one year', 400);
  }
  if (!nativeRenewalHostAllowed(host)) return undefined;
  return { version: 1, leaseLifetimeSeconds: seconds, ...(purpose === undefined ? {} : { purpose }) };
}

type Artifact = Record<string, unknown> & { expiresAt: string };

export async function recordNativeRenewal(
  tx: Prisma.TransactionClient,
  input: { userId: string; requestId: string; host: string; delegation: Artifact; leaseLifetimeSeconds: number; sensitiveConfirmed: boolean },
  signOwner: (message: string) => Promise<string>,
  fetchImpl?: typeof fetch,
): Promise<{ leaseCid: string; nodeIdentity: ApprovalResultRenewal['receipt']['nodeIdentity'] }> {
  const stage = await prepareRenewalStage({ ...input, appAdmits: true, now: new Date(), fetchImpl });
  const signed = signLease(stage, await signOwner(stage.leaseSiwe));
  await reserveRenewalLeaseInTransaction(tx, {
    approvalRequestId: null, sessionId: null, userId: input.userId, nodeOrigin: input.host, stage: signed,
    native: { requestId: input.requestId, revokeUntil: new Date(Math.max(Date.parse(input.delegation.expiresAt), Date.parse(signed.leaseExpiresAt))) },
  });
  return { leaseCid: signed.leaseCid!, nodeIdentity: stage.nodeIdentity };
}

export async function deliverNativeRenewal(
  tx: Prisma.TransactionClient, input: { userId: string; requestId: string; grantId: string; originalCid: string; leaseCid: string; nodeIdentity: ApprovalResultRenewal['receipt']['nodeIdentity'] },
): Promise<ApprovalResultRenewal> {
  const lease = await tx.renewalLease.findFirst({
    where: {
      leaseCid: input.leaseCid, userId: input.userId, originalCid: input.originalCid,
      nativeRenewal: { is: { requestId: input.requestId, grantId: null, stopRequested: false } }, revokedAt: null, neverAdmittedAt: null,
    },
  });
  if (!lease) throw new RenewalLeaseError('renewal_stopped', 'Renewal was stopped for this lease', 409);
  const leaseAuthorization = await reservedLeaseAuthorization(tx, input.userId, lease.leaseCid);
  await tx.nativeRenewalLease.update({
    where: { leaseCid: lease.leaseCid },
    data: { grantId: input.grantId, deliveredAt: new Date() },
  });
  return {
    version: 1,
    approvedLeaseLifetimeSeconds: lease.leaseLifetimeSeconds,
    approvedAt: lease.approvedAt.toISOString(),
    receipt: {
      originalCid: lease.originalCid, leaseCid: lease.leaseCid, leaseAuthorization, leaseGeneration: 1,
      leaseExpiresAt: lease.leaseExpiresAt.toISOString(), nodeIdentity: input.nodeIdentity,
    },
  };
}
