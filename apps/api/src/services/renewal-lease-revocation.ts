// Stopping an owner's renewal leases (TC-2946). A lease lets the node's renewer keep one approved
// grant alive; stopping it revokes the LEASE delegation at the node it was registered with, so the
// node stops renewing and drops the time renewal added. The grant itself is not revoked: it ends at
// its own signed end. Only the owner who signed a lease can revoke it, without any proof, so the
// revocation is a SIWE from the lease's owner key whose URI is `ucan:<lease CID>`.
//
// A lease counts as stopped only once its node answered the revocation with success; anything else
// (refusal, timeout, unreachable node, a wallet that must sign) leaves `revokedAt` empty, so a retry
// sends it again. Revoking an already-revoked lease again is harmless at the node.
import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@openkey/db';
import { siweToDelegationHeaders } from '@tinycloud/node-sdk-wasm';
import { buildOwnerRevocationSiwe } from '@openkey/capability-review';
import { verifyMessage } from 'viem';
import { SiweMessage } from 'siwe';
import { SIWE_DOMAIN } from '../routes/delegate-session';
import { signManagedKey } from './managed-key-signing';
import { isKnownTinyCloudActivationHost } from './tinycloud-hosts';

const NODE_CALL_TIMEOUT_MS = 5_000;
/** How long a revocation message stays valid; the node checks it. */
const REVOCATION_LIFETIME_MS = 5 * 60_000;
const OWNER_DID = /^did:pkh:eip155:([1-9][0-9]*):(0x[0-9a-fA-F]{40})$/;

export type LeaseRevocationDatabase = Pick<PrismaClient, 'renewalLease' | 'ethereumKey'>;

/** Which of the account's leases to stop. */
export type LeaseScope =
  | { kind: 'lease'; leaseCid: string }
  | { kind: 'session'; sessionId: string }
  /** Every lease not approved under the session that stays signed in (sign out other sessions). */
  | { kind: 'other-sessions'; keepSessionId: string }
  | { kind: 'all' };

/**
 * Why a lease was not stopped. `wallet_required`: an external wallet signed it, so only that wallet
 * can revoke it. `node_unavailable`: the node did not confirm (refused, failed, timed out or unreachable).
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
}

const defaultDeps: LeaseRevocationDeps = { signManaged: signManagedKey, fetch, now: () => new Date() };

function scopeWhere(scope: LeaseScope) {
  switch (scope.kind) {
    case 'lease': return { leaseCid: scope.leaseCid };
    case 'session': return { sessionId: scope.sessionId };
    case 'other-sessions': return { OR: [{ sessionId: null }, { sessionId: { not: scope.keepSessionId } }] };
    case 'all': return {};
  }
}

/** The leases in `scope` that still need stopping: not yet confirmed revoked and not yet past their end. */
export function liveLeaseWhere(userId: string, scope: LeaseScope, now: Date) {
  return { userId, revokedAt: null, leaseExpiresAt: { gt: now }, ...scopeWhere(scope) };
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

function ownerAddress(ownerDid: string): string | null {
  return OWNER_DID.exec(ownerDid)?.[2]?.toLowerCase() ?? null;
}

/** Sends one signed revocation to the lease's node. True only when the node answered success. */
async function sendRevocation(nodeOrigin: string, siwe: string, signature: string, deps: Pick<LeaseRevocationDeps, 'fetch'>): Promise<boolean> {
  if (!isKnownTinyCloudActivationHost(nodeOrigin)) return false;
  try {
    // No body and no JSON content type: the node's JSON `/revoke` is a different (policy) route.
    const response = await deps.fetch(`${nodeOrigin}/revoke`, {
      method: 'POST',
      headers: siweToDelegationHeaders({ siwe, signature }) as Record<string, string>,
      redirect: 'error',
      signal: AbortSignal.timeout(NODE_CALL_TIMEOUT_MS),
    });
    await response.body?.cancel();
    return response.ok;
  } catch {
    return false;
  }
}

async function markRevoked(db: LeaseRevocationDatabase, leaseCid: string, at: Date) {
  await db.renewalLease.updateMany({ where: { leaseCid, revokedAt: null }, data: { revokedAt: at } });
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
  const now = deps.now();
  const leases = await db.renewalLease.findMany({ where: liveLeaseWhere(userId, scope, now), orderBy: { createdAt: 'asc' } });
  const report: LeaseRevocationReport = { stopped: [], notStopped: [] };
  if (leases.length === 0) return report;
  const keys = await db.ethereumKey.findMany({
    where: { userId },
    select: { address: true, keyType: true, sealedBlob: true, userId: true, sealingContext: true },
  });
  await Promise.all(leases.map(async (lease) => {
    const address = ownerAddress(lease.ownerDid);
    const key = keys.find((candidate) => candidate.address.toLowerCase() === address);
    if (!key || key.keyType !== 'MANAGED' || !key.sealedBlob) {
      report.notStopped.push({ leaseCid: lease.leaseCid, reason: 'wallet_required' });
      return;
    }
    let revoked = false;
    try {
      const siwe = leaseRevocationSiwe(lease, now);
      revoked = await sendRevocation(lease.nodeOrigin, siwe, await deps.signManaged(key, key.sealedBlob, siwe), deps);
    } catch {
      revoked = false;
    }
    if (!revoked) {
      report.notStopped.push({ leaseCid: lease.leaseCid, reason: 'node_unavailable' });
      return;
    }
    await markRevoked(db, lease.leaseCid, deps.now());
    report.stopped.push(lease.leaseCid);
  }));
  return report;
}

export class LeaseRevocationError extends Error {
  constructor(readonly code: 'not_found' | 'invalid_signature' | 'node_unavailable', readonly status: 400 | 404 | 503) { super(code); }
}

/**
 * Accepts an external wallet's signature on the revocation message for one of the user's live leases,
 * and sends it to the lease's node. The message must be an owner revocation of exactly this lease by its
 * owner, for OpenKey's domain, and still valid; the signature must recover to the owner.
 */
export async function revokeLeaseWithWalletSignature(
  db: LeaseRevocationDatabase,
  userId: string,
  input: { leaseCid: string; siwe: string; signature: string },
  deps: Pick<LeaseRevocationDeps, 'fetch' | 'now'> = defaultDeps,
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
  if (!await sendRevocation(lease.nodeOrigin, input.siwe, input.signature, deps)) throw new LeaseRevocationError('node_unavailable', 503);
  await markRevoked(db, lease.leaseCid, deps.now());
}
