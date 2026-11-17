// Renewal at an app sign-in (TC-2872): the renewal checkbox on OpenKey's own sign-in frame or popup.
//
// The app asks for renewal with its longest lease at /authorize-sign-prepare; the owner's choice is sealed with
// the preview; a leased choice makes /authorize-sign register the signed grant with its node, then sign, record
// and admit an owner lease for exactly that grant before anything is returned. An external wallet signs the lease
// in a second step (/authorize-sign-renewal). While renewal leases are off nothing here runs: the ask is ignored.
import { randomUUID } from 'node:crypto';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { completeSessionSetup } from '@tinycloud/node-sdk-wasm';
import { SiweMessage } from 'siwe';
import {
  MAX_LEASE_SECONDS,
  RENEWAL_FAILED_MESSAGE,
  RenewalLeaseError,
  admitLease,
  prepareRenewalStage,
  renewalLeasesEnabled,
  renewalUnavailableMessage,
  signLease,
  type ApprovalResultRenewal,
  type RenewalStage,
} from './renewal-lease';
import { logError } from '../log';
import { defaultDeps, reserveRenewalLease, revokeRenewalLeases, type LeaseRevocationDatabase } from './renewal-lease-revocation';
import { isKnownTinyCloudActivationHost } from './tinycloud-hosts';
import { activateSessionWithinTimeout } from './tinycloud-node-timeouts';
import type { SignInRenewalRequest } from './authorization-signing';

/** How long an external wallet has to sign the lease after signing the grant. */
const PENDING_LEASE_TTL_MS = 10 * 60 * 1000;

type TargetJwk = { kty: 'OKP'; crv: 'Ed25519'; x: string };

let database: LeaseRevocationDatabase | undefined;
function db() {
  database ??= createPrismaClient();
  return database;
}

/**
 * The app's renewal ask for this sign-in, or undefined when there is none to bind: leases off (the ask is ignored
 * and the sign-in is exactly as before), no ask, or a node OpenKey does not set leases up on (no box is offered).
 * A malformed ask, one on a prepared CLI handoff, or one from an app that does not accept a changed expiry (renewing
 * sensitive access shortens the window, spec D6) is refused.
 */
export function bindSignInRenewalRequest(value: unknown, input: { host: string; handoff: boolean; expiryChangeable: boolean }): SignInRenewalRequest | undefined {
  if (!renewalLeasesEnabled() || value === undefined) return undefined;
  if (input.handoff) throw new RenewalLeaseError('request_binding', 'Renewal is only offered at app sign-in, not on redirect or handoff sign-ins.', 400);
  if (!input.expiryChangeable) throw new RenewalLeaseError('request_binding', 'Renewal requires expiryChangeable: true in the sign-in request.', 400);
  const ask = value !== null && typeof value === 'object' ? value as Record<string, unknown> : null;
  const seconds = ask?.leaseLifetimeSeconds;
  if (!ask || ask.version !== 1 || Object.keys(ask).length !== 2 || typeof seconds !== 'number' || !Number.isSafeInteger(seconds) ||
    seconds <= 0 || seconds > MAX_LEASE_SECONDS) {
    throw new RenewalLeaseError('invalid_renewal_request', 'renewal must be { version: 1, leaseLifetimeSeconds } with at most one year', 400);
  }
  if (!isKnownTinyCloudActivationHost(input.host) || new URL(input.host).origin !== input.host) return undefined;
  return { version: 1, leaseLifetimeSeconds: seconds };
}

interface SignInLeaseOwner {
  userId: string;
  sessionId: string | null;
  host: string;
  jwk: unknown;
}

interface PendingLease extends SignInLeaseOwner {
  stage: RenewalStage;
  expiresAt: number;
}

const pendingLeases = new Map<string, PendingLease>();

function targetJwk(jwk: unknown): TargetJwk {
  const key = jwk as Partial<TargetJwk> | null;
  if (!key || key.kty !== 'OKP' || key.crv !== 'Ed25519' || typeof key.x !== 'string') {
    throw new RenewalLeaseError('invalid_delegation', 'The session key cannot hold a renewed grant', 400);
  }
  return { kty: 'OKP', crv: 'Ed25519', x: key.x };
}

/** What a leased sign-in returns beside the grant: the admitted lease, or the lease the external wallet signs next. */
export type SignInLease =
  | { renewal: ApprovalResultRenewal }
  | { renewalSignature: { message: string; leaseLifetimeSeconds: number; renewalToken: string } };

/**
 * Registers the signed grant with its node and sets up its owner lease (scope: `tinycloud.delegation/renew` on
 * this grant's CID only). `signOwner` signs the lease with the managed key; without it the lease message is held
 * for the owner's wallet, bound to this user, for one /authorize-sign-renewal call.
 */
export async function setUpSignInLease(
  owner: SignInLeaseOwner & {
    signedMessage: string;
    signature: string;
    spaceId: string;
    leaseLifetimeSeconds: number;
    signOwner?: (message: string) => Promise<string>;
  },
): Promise<SignInLease> {
  if (!renewalLeasesEnabled()) throw new RenewalLeaseError('renewal_disabled', renewalUnavailableMessage('sign-in', 'after-signing'), 400);
  const jwk = targetJwk(owner.jwk);
  const session = completeSessionSetup({
    siwe: owner.signedMessage,
    jwk,
    spaceId: owner.spaceId,
    verificationMethod: new SiweMessage(owner.signedMessage).uri,
    signature: owner.signature,
  } as Parameters<typeof completeSessionSetup>[0]);
  // The node must hold the grant before it admits a lease for it. The app activates the same grant again later;
  // the node stores a delegation once.
  const activation = await activateSessionWithinTimeout(owner.host, session.delegationHeader);
  const stage = await prepareRenewalStage({
    userId: owner.userId,
    host: owner.host,
    leaseLifetimeSeconds: owner.leaseLifetimeSeconds,
    delegation: {
      delegationHeader: session.delegationHeader,
      delegationCid: session.delegationCid,
      spaceId: owner.spaceId,
      siwe: owner.signedMessage,
      hostActivated: activation.success === true,
    },
    now: new Date(),
  });
  const leaseOwner = { userId: owner.userId, sessionId: owner.sessionId, host: owner.host, jwk };
  if (!owner.signOwner) {
    const now = Date.now();
    for (const [token, pending] of pendingLeases) if (pending.expiresAt <= now) pendingLeases.delete(token);
    const renewalToken = `okr_${randomUUID().replace(/-/g, '')}${randomUUID().replace(/-/g, '')}`;
    pendingLeases.set(renewalToken, { ...leaseOwner, stage, expiresAt: now + PENDING_LEASE_TTL_MS });
    return { renewalSignature: { message: stage.leaseSiwe, leaseLifetimeSeconds: stage.approvedLeaseLifetimeSeconds, renewalToken } };
  }
  return { renewal: await finishSignInLease(leaseOwner, signLease(stage, await owner.signOwner(stage.leaseSiwe))) };
}

/**
 * The lease an external wallet is asked to sign, taken once: only by the user whose sign-in it belongs to, and only
 * before it lapses. A taken lease cannot be retried; the owner signs in again.
 */
export function takePendingSignInLease(renewalToken: unknown, userId: string): (SignInLeaseOwner & { stage: RenewalStage }) | null {
  if (typeof renewalToken !== 'string') return null;
  const pending = pendingLeases.get(renewalToken);
  if (!pending || pending.userId !== userId) return null;
  pendingLeases.delete(renewalToken);
  if (pending.expiresAt <= Date.now()) return null;
  const { expiresAt: _expiresAt, ...lease } = pending;
  return lease;
}

/**
 * Records the signed lease for its owner, has the node admit it, then confirms the record. A lease stopped in
 * between is refused at either end, so the sign-in fails and no receipt is returned. When admission or the confirm
 * fails after the reservation, the node may still hold the lease (an answer lost after it stored it), so the lease is
 * stopped before the failure is returned: no lease keeps renewing a grant this sign-in never handed out. A lease an
 * external wallet signed can only be stopped by that wallet; Settings lists it until then.
 */
export async function finishSignInLease(owner: SignInLeaseOwner, stage: RenewalStage): Promise<ApprovalResultRenewal> {
  if (!renewalLeasesEnabled()) throw new RenewalLeaseError('renewal_disabled', renewalUnavailableMessage('sign-in', 'after-signing'), 400);
  await reserveRenewalLease(db(), { approvalRequestId: null, userId: owner.userId, sessionId: owner.sessionId, nodeOrigin: owner.host, stage });
  try {
    const renewal = await admitLease(stage, { nodeOrigin: owner.host, targetPublicJwk: targetJwk(owner.jwk) });
    const confirmed = await db().renewalLease.updateMany({
      where: {
        leaseCid: stage.leaseCid, userId: owner.userId, approvalRequestId: null, ownerDid: `did:pkh:eip155:${stage.chainId}:${stage.ownerAddress}`,
        originalCid: stage.originalCid, nodeOrigin: owner.host, revokedAt: null, neverAdmittedAt: null, admittedAt: null,
      },
      data: { admittedAt: new Date(), leaseAuthorization: null, sessionId: owner.sessionId },
    });
    if (confirmed.count !== 1) throw new RenewalLeaseError('renewal_stopped', 'Renewal was turned off for this sign-in. To turn it back on, sign in again.', 409);
    return renewal;
  } catch (error) {
    if (stage.leaseCid) {
      // The same fetch as this sign-in's own node calls, looked up now.
      await revokeRenewalLeases(db(), owner.userId, { kind: 'lease', leaseCid: stage.leaseCid }, { ...defaultDeps, fetch: globalThis.fetch })
        .catch((cleanup: unknown) => logError('warn', 'signin_renewal_failed', cleanup));
    }
    throw error;
  }
}

/**
 * What the widget gets when renewal could not be set up. A caller error keeps its own answer; anything else is the
 * owner-facing failure, and no signature or grant is returned with it.
 */
export function signInRenewalFailure(error: unknown): { status: 400 | 409 | 503; body: { error: string; code: string } } {
  if (error instanceof RenewalLeaseError && error.status !== 503) return { status: error.status, body: { error: error.message, code: error.code } };
  logError('warn', 'signin_renewal_failed', error);
  return { status: 503, body: { error: RENEWAL_FAILED_MESSAGE, code: 'renewal_failed' } };
}

/** Test helper: forgets every lease waiting for a wallet signature. */
export function _resetPendingSignInLeasesForTests(): void {
  pendingLeases.clear();
}
