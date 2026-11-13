// Recording and stopping an owner's renewal leases (TC-2946). A lease lets the node's renewer keep one approved
// grant alive; stopping it revokes the LEASE delegation at the node it was registered with, so the node stops
// renewing and drops the time renewal added. The grant itself is not revoked: it ends at its own signed end.
// Only the owner who signed a lease can revoke it, without any proof, so the revocation is a SIWE from the
// lease's owner key whose URI is `ucan:<lease CID>`.
//
// A lease is recorded (reserved) before its node admission, under the owner's user-row lock, so a lease whose
// admission outcome is unknown can always be found. Until the approval that admitted it is saved
// (`admittedAt`), the node may or may not hold it, and it refuses to revoke a lease it doesn't hold. So such a
// lease is settled by replaying its admission (the same signed bytes; idempotent at the node) and revoking it
// straight after, both under the user lock that new reservations also take.
//
// A lease is settled only by the node: `revokedAt` once its node answered the revocation with success, or
// `neverAdmittedAt` once the node refused to admit it and held nothing to revoke. Anything else (timeout,
// unreachable node, a wallet that must sign) leaves it unsettled, so a retry sends it again. Revoking an
// already-revoked lease again is harmless at the node.
import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@openkey/db';
import { siweToDelegationHeaders } from '@tinycloud/node-sdk-wasm';
import { buildOwnerRevocationSiwe } from '@openkey/capability-review';
import { symmetricDecrypt, symmetricEncrypt } from 'better-auth/crypto';
import { verifyMessage } from 'viem';
import { SiweMessage } from 'siwe';
import { SIWE_DOMAIN } from '../routes/delegate-session';
import { signManagedKey } from './managed-key-signing';
import { RenewalLeaseError, type RenewalStage } from './renewal-lease';
import { isKnownTinyCloudActivationHost } from './tinycloud-hosts';

const NODE_CALL_TIMEOUT_MS = 5_000;
/** How long a revocation message stays valid; the node checks it. */
const REVOCATION_LIFETIME_MS = 5 * 60_000;
const OWNER_DID = /^did:pkh:eip155:([1-9][0-9]*):(0x[0-9a-fA-F]{40})$/;

export type LeaseRevocationDatabase = Pick<PrismaClient, 'renewalLease' | 'ethereumKey' | '$transaction'>;

/** Which of the account's leases to stop. */
export type LeaseScope =
  | { kind: 'lease'; leaseCid: string }
  | { kind: 'session'; sessionId: string }
  /** Every lease not approved under the session that stays signed in (sign out other sessions). */
  | { kind: 'other-sessions'; keepSessionId: string }
  | { kind: 'all' };

/**
 * Why a lease was not stopped. `wallet_required`: an external wallet signed it, so only that wallet
 * can revoke it. `node_unavailable`: the node did not settle it (failed, timed out or unreachable).
 */
export type LeaseNotStoppedReason = 'wallet_required' | 'node_unavailable';

export interface LeaseRevocationReport {
  stopped: string[];
  notStopped: Array<{ leaseCid: string; reason: LeaseNotStoppedReason }>;
}

export interface LeaseRevocationDeps {
  signManaged: (key: { userId: string | null; sealingContext: string | null }, sealedBlob: string, message: string) => Promise<string>;
  fetch: typeof fetch;
  now: () => Date;
  /** Encrypts and decrypts the signed lease kept while its admission is unconfirmed. */
  seal: (plaintext: string) => Promise<string>;
  open: (sealed: string) => Promise<string>;
}

async function secretKey() {
  // Loaded on use: auth.ts loads this module (sign-out hooks), and its context holds the at-rest secret.
  const { auth } = await import('../auth');
  return (await auth.$context).secretConfig;
}

const defaultDeps: LeaseRevocationDeps = {
  signManaged: signManagedKey,
  fetch,
  now: () => new Date(),
  seal: async (data) => symmetricEncrypt({ key: await secretKey(), data }),
  open: async (data) => symmetricDecrypt({ key: await secretKey(), data }),
};

function scopeWhere(scope: LeaseScope) {
  switch (scope.kind) {
    case 'lease': return { leaseCid: scope.leaseCid };
    case 'session': return { sessionId: scope.sessionId };
    case 'other-sessions': return { OR: [{ sessionId: null }, { sessionId: { not: scope.keepSessionId } }] };
    case 'all': return {};
  }
}

/** The leases in `scope` that may still renew: not settled by the node and not past their end. */
export function liveLeaseWhere(userId: string, scope: LeaseScope, now: Date) {
  return { userId, revokedAt: null, neverAdmittedAt: null, leaseExpiresAt: { gt: now }, ...scopeWhere(scope) };
}

/** The exact owner-revocation message for one lease; `issuedAt` bounds its life. */
export function leaseRevocationSiwe(lease: { ownerDid: string; leaseCid: string }, issuedAt: Date, nonce = randomBytes(16).toString('hex')): string {
  return buildOwnerRevocationSiwe({
    kind: 'owner-revocation',
    ownerDid: lease.ownerDid,
    cid: lease.leaseCid,
    nonce,
    expiresAt: new Date(issuedAt.getTime() + REVOCATION_LIFETIME_MS).toISOString(),
  }, SIWE_DOMAIN, issuedAt);
}

type Transaction = Parameters<Parameters<LeaseRevocationDatabase['$transaction']>[0]>[0];

/** Holds the owner's user row for the rest of the transaction: lease reservations and settling take it first. */
async function lockOwner(tx: Transaction, userId: string) {
  await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR UPDATE`;
}

/**
 * Records the signed lease for its owner before the node is asked to admit it, under the owner's user lock.
 * Idempotent per lease CID, so a retry after a crash finds the same record. A lease already settled (stopped,
 * or refused by the node) is never admitted again: the approval fails and nothing is approved.
 */
export async function reserveRenewalLease(
  db: Pick<PrismaClient, '$transaction'>,
  input: { approvalRequestId: string; userId: string; sessionId: string | null; nodeOrigin: string; stage: RenewalStage },
  deps: Pick<LeaseRevocationDeps, 'seal'> = defaultDeps,
): Promise<void> {
  const { stage } = input;
  if (!stage.leaseCid || !stage.leaseAuthorization || typeof stage.delegation.siwe !== 'string') {
    throw new RenewalLeaseError('lease_unsigned', 'Renewal lease is not signed', 409);
  }
  const leaseCid = stage.leaseCid;
  const sealed = await deps.seal(stage.leaseAuthorization);
  await db.$transaction(async (tx) => {
    await lockOwner(tx, input.userId);
    const existing = await tx.renewalLease.findUnique({ where: { leaseCid } });
    if (existing) {
      if (existing.userId !== input.userId || existing.revokedAt || existing.neverAdmittedAt) {
        throw new RenewalLeaseError('renewal_stopped', 'Renewal was stopped for this lease', 409);
      }
      return;
    }
    await tx.renewalLease.create({ data: {
      leaseCid,
      userId: input.userId,
      sessionId: input.sessionId,
      approvalRequestId: input.approvalRequestId,
      ownerDid: `did:pkh:eip155:${stage.chainId}:${stage.ownerAddress}`,
      originalCid: stage.originalCid,
      nodeOrigin: input.nodeOrigin,
      nodeDid: stage.nodeIdentity.nodeDid,
      renewerDid: stage.nodeIdentity.renewerDid,
      leaseLifetimeSeconds: stage.approvedLeaseLifetimeSeconds,
      approvedAt: new Date(stage.approvedAt),
      leaseExpiresAt: new Date(stage.leaseExpiresAt),
      grantSiwe: stage.delegation.siwe as string,
      leaseAuthorization: sealed,
    } });
  });
}

function ownerAddress(ownerDid: string): string | null {
  return OWNER_DID.exec(ownerDid)?.[2]?.toLowerCase() ?? null;
}

type NodeAnswer = 'ok' | 'refused' | 'unavailable';

/** A definite answer: 2xx, or a refusal that retrying the same request can't change. */
function answer(status: number): NodeAnswer {
  if (status >= 200 && status < 300) return 'ok';
  return status >= 400 && status < 500 && status !== 408 && status !== 429 ? 'refused' : 'unavailable';
}

async function callNode(deps: Pick<LeaseRevocationDeps, 'fetch'>, nodeOrigin: string, path: '/revoke' | '/delegate', headers: Record<string, string>): Promise<NodeAnswer> {
  if (!isKnownTinyCloudActivationHost(nodeOrigin)) return 'unavailable';
  try {
    // No body and no JSON content type: the node's JSON `/revoke` is a different (policy) route.
    const response = await deps.fetch(`${nodeOrigin}${path}`, { method: 'POST', headers, redirect: 'error', signal: AbortSignal.timeout(NODE_CALL_TIMEOUT_MS) });
    await response.body?.cancel();
    return answer(response.status);
  } catch {
    return 'unavailable';
  }
}

type LeaseRow = Awaited<ReturnType<LeaseRevocationDatabase['renewalLease']['findMany']>>[number];

/**
 * Settles one lease under the owner's lock. An unconfirmed admission is replayed first and the revocation sent
 * straight after it, so the lease can be live for at most that one round trip. True once the node settled it.
 */
async function settle(tx: Transaction, lease: LeaseRow, revocation: { siwe: string; signature: string }, deps: Pick<LeaseRevocationDeps, 'fetch' | 'now' | 'open'>): Promise<boolean> {
  let admission: NodeAnswer = 'ok';
  if (!lease.admittedAt && lease.leaseAuthorization) {
    admission = await callNode(deps, lease.nodeOrigin, '/delegate', { Authorization: await deps.open(lease.leaseAuthorization) });
  }
  const revoked = await callNode(deps, lease.nodeOrigin, '/revoke', siweToDelegationHeaders(revocation) as Record<string, string>);
  const at = deps.now();
  if (revoked === 'ok') {
    await tx.renewalLease.updateMany({ where: { leaseCid: lease.leaseCid, revokedAt: null }, data: { revokedAt: at, leaseAuthorization: null } });
    return true;
  }
  // The node refused to admit it and holds no lease to revoke: this signed lease can never renew.
  if (!lease.admittedAt && admission === 'refused' && revoked === 'refused') {
    await tx.renewalLease.updateMany({ where: { leaseCid: lease.leaseCid, revokedAt: null }, data: { neverAdmittedAt: at, leaseAuthorization: null } });
    return true;
  }
  return false;
}

/** Long enough for each lease's two node calls; the user lock is held throughout. */
function settleTimeout(leases: number) {
  return leases * 3 * NODE_CALL_TIMEOUT_MS + 5_000;
}

/**
 * Stops every live lease of `userId` in `scope` that an OpenKey-held key signed, and reports each one.
 * Leases an external wallet signed are reported `wallet_required` and left untouched.
 */
export async function revokeRenewalLeases(
  db: LeaseRevocationDatabase,
  userId: string,
  scope: LeaseScope,
  deps: LeaseRevocationDeps = defaultDeps,
): Promise<LeaseRevocationReport> {
  const report: LeaseRevocationReport = { stopped: [], notStopped: [] };
  const candidates = await db.renewalLease.findMany({ where: liveLeaseWhere(userId, scope, deps.now()), select: { leaseCid: true } });
  if (candidates.length === 0) return report;
  const keys = await db.ethereumKey.findMany({
    where: { userId },
    select: { address: true, keyType: true, sealedBlob: true, userId: true, sealingContext: true },
  });
  await db.$transaction(async (tx) => {
    await lockOwner(tx, userId);
    // Re-read under the lock: another attempt may have settled some meanwhile.
    const leases = await tx.renewalLease.findMany({ where: liveLeaseWhere(userId, scope, deps.now()), orderBy: { createdAt: 'asc' } });
    for (const lease of leases) {
      const address = ownerAddress(lease.ownerDid);
      const key = keys.find((candidate) => candidate.address.toLowerCase() === address);
      if (!key || key.keyType !== 'MANAGED' || !key.sealedBlob) {
        report.notStopped.push({ leaseCid: lease.leaseCid, reason: 'wallet_required' });
        continue;
      }
      let settled = false;
      try {
        const siwe = leaseRevocationSiwe(lease, deps.now());
        settled = await settle(tx, lease, { siwe, signature: await deps.signManaged(key, key.sealedBlob, siwe) }, deps);
      } catch {
        settled = false;
      }
      if (settled) report.stopped.push(lease.leaseCid);
      else report.notStopped.push({ leaseCid: lease.leaseCid, reason: 'node_unavailable' });
    }
  }, { timeout: settleTimeout(candidates.length), maxWait: 10_000 });
  return report;
}

export class LeaseRevocationError extends Error {
  constructor(readonly code: 'not_found' | 'invalid_signature' | 'node_unavailable', readonly status: 400 | 404 | 503) { super(code); }
}

/**
 * Accepts an external wallet's signature on the revocation message for one of the user's live leases,
 * and settles the lease with it. The message must be the owner revocation rebuilt from this lease, still
 * valid, and the signature must recover to the owner.
 */
export async function revokeLeaseWithWalletSignature(
  db: LeaseRevocationDatabase,
  userId: string,
  input: { leaseCid: string; siwe: string; signature: string },
  deps: Pick<LeaseRevocationDeps, 'fetch' | 'now' | 'open'> = defaultDeps,
): Promise<void> {
  const now = deps.now();
  const lease = await db.renewalLease.findFirst({ where: liveLeaseWhere(userId, { kind: 'lease', leaseCid: input.leaseCid }, now) });
  if (!lease) throw new LeaseRevocationError('not_found', 404);
  let message: SiweMessage;
  try { message = new SiweMessage(input.siwe); } catch { throw new LeaseRevocationError('invalid_signature', 400); }
  // Rebuilt from the lease itself, so the owner, chain, domain and `ucan:<lease CID>` are this lease's;
  // only the signed nonce and issue time come from the message.
  const issuedAt = new Date(message.issuedAt ?? '');
  if (Number.isNaN(issuedAt.getTime()) || leaseRevocationSiwe(lease, issuedAt, message.nonce) !== input.siwe ||
    Date.parse(message.expirationTime ?? '') <= now.getTime()) {
    throw new LeaseRevocationError('invalid_signature', 400);
  }
  const valid = /^0x[0-9a-fA-F]{130}$/.test(input.signature) &&
    await verifyMessage({ address: message.address as `0x${string}`, message: input.siwe, signature: input.signature as `0x${string}` }).catch(() => false);
  if (!valid) throw new LeaseRevocationError('invalid_signature', 400);
  const settled = await db.$transaction(async (tx) => {
    await lockOwner(tx, userId);
    const current = await tx.renewalLease.findFirst({ where: liveLeaseWhere(userId, { kind: 'lease', leaseCid: input.leaseCid }, deps.now()) });
    if (!current) return true;
    return settle(tx, current, { siwe: input.siwe, signature: input.signature }, deps).catch(() => false);
  }, { timeout: settleTimeout(1), maxWait: 10_000 });
  if (!settled) throw new LeaseRevocationError('node_unavailable', 503);
}
