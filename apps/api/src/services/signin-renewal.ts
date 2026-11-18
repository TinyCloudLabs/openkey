// Renewal at an app sign-in (TC-2872): the renewal checkbox on OpenKey's own sign-in frame or popup.
//
// The app asks for renewal with its longest lease at /authorize-sign-prepare; the owner's choice is sealed with
// the preview. A leased choice makes /authorize-sign also sign an owner lease for exactly the signed grant, or hand
// the lease message to the owner's wallet for /authorize-sign-renewal. OpenKey returns the signed lease beside the
// grant and keeps nothing: the app registers the grant with its node and has the node admit the lease, and the
// node does all the renewing. While renewal leases are off nothing here runs: the ask is ignored.
import { randomUUID } from 'node:crypto';
import { completeSessionSetup } from '@tinycloud/node-sdk-wasm';
import { verifyMessage } from 'ethers';
import { SiweMessage } from 'siwe';
import {
  MAX_LEASE_SECONDS,
  RENEWAL_FAILED_MESSAGE,
  RenewalLeaseError,
  prepareRenewalStage,
  renewalLeasesEnabled,
  renewalUnavailableMessage,
  signLease,
  type ApprovalResultRenewal,
  type RenewalStage,
} from './renewal-lease';
import { logError, logSignInLeaseSigned } from '../log';
import { isKnownTinyCloudActivationHost } from './tinycloud-hosts';
import type { SignInRenewalRequest } from './authorization-signing';

/** How long an external wallet has to sign the lease after signing the grant. */
const PENDING_LEASE_TTL_MS = 10 * 60 * 1000;

type TargetJwk = { kty: 'OKP'; crv: 'Ed25519'; x: string };

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

interface PendingLease {
  userId: string;
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

/** What a leased sign-in returns beside the grant: the signed lease, or the lease the external wallet signs next. */
export type SignInLease =
  | { renewal: ApprovalResultRenewal }
  | { renewalSignature: { message: string; leaseLifetimeSeconds: number; renewalToken: string } };

/**
 * The signed lease in the shape of the js-sdk approval-renewal codec. Nothing has been sent to the node: the app
 * passes these fields, with its own grant, to `admitOwnerRenewalLease`, whose receipt carries the same values.
 * OpenKey keeps no other record of the lease, so its signing is logged: the lease CID and which key signed it.
 */
export function signedSignInLease(stage: RenewalStage, signer: 'managed' | 'wallet'): ApprovalResultRenewal {
  if (!stage.leaseAuthorization || !stage.leaseCid) throw new RenewalLeaseError('lease_unsigned', 'Renewal lease is not signed', 409);
  logSignInLeaseSigned(stage.leaseCid, signer, stage.approvedLeaseLifetimeSeconds);
  return {
    version: 1,
    approvedLeaseLifetimeSeconds: stage.approvedLeaseLifetimeSeconds,
    approvedAt: stage.approvedAt,
    receipt: {
      originalCid: stage.originalCid,
      leaseCid: stage.leaseCid,
      leaseAuthorization: stage.leaseAuthorization,
      leaseExpiresAt: stage.leaseExpiresAt,
      leaseGeneration: 1,
      nodeIdentity: { ...stage.nodeIdentity },
    },
  };
}

/**
 * The owner lease for the signed grant (scope: `tinycloud.delegation/renew` on this grant's CID only, for the node's
 * renewer). The node is only asked who its renewer is. `signOwner` signs the lease with the managed key; without it
 * the lease message is held for the owner's wallet, bound to this user, for one /authorize-sign-renewal call.
 */
export async function setUpSignInLease(owner: {
  userId: string;
  host: string;
  jwk: unknown;
  signedMessage: string;
  signature: string;
  spaceId: string;
  leaseLifetimeSeconds: number;
  signOwner?: (message: string) => Promise<string>;
}): Promise<SignInLease> {
  if (!renewalLeasesEnabled()) throw new RenewalLeaseError('renewal_disabled', renewalUnavailableMessage('sign-in', 'after-signing'), 400);
  const session = completeSessionSetup({
    siwe: owner.signedMessage,
    jwk: targetJwk(owner.jwk),
    spaceId: owner.spaceId,
    verificationMethod: new SiweMessage(owner.signedMessage).uri,
    signature: owner.signature,
  } as Parameters<typeof completeSessionSetup>[0]);
  const stage = await prepareRenewalStage({
    userId: owner.userId,
    host: owner.host,
    leaseLifetimeSeconds: owner.leaseLifetimeSeconds,
    delegation: {
      delegationHeader: session.delegationHeader,
      delegationCid: session.delegationCid,
      spaceId: owner.spaceId,
      siwe: owner.signedMessage,
    },
    now: new Date(),
    appAdmits: true,
  });
  if (!owner.signOwner) {
    const now = Date.now();
    for (const [token, pending] of pendingLeases) if (pending.expiresAt <= now) pendingLeases.delete(token);
    const renewalToken = `okr_${randomUUID().replace(/-/g, '')}${randomUUID().replace(/-/g, '')}`;
    pendingLeases.set(renewalToken, { userId: owner.userId, stage, expiresAt: now + PENDING_LEASE_TTL_MS });
    return { renewalSignature: { message: stage.leaseSiwe, leaseLifetimeSeconds: stage.approvedLeaseLifetimeSeconds, renewalToken } };
  }
  return { renewal: signedSignInLease(signLease(stage, await owner.signOwner(stage.leaseSiwe)), 'managed') };
}

/**
 * The lease an external wallet is asked to sign, taken with the owner's signature on it: only by the user whose
 * sign-in it belongs to, and only before it lapses. A signature from another wallet leaves it waiting for the right
 * one; a taken lease cannot be retried (the owner signs in again). Synchronous, so two requests can't both take it.
 */
export function takePendingSignInLease(renewalToken: unknown, userId: string, signature: string): RenewalStage | 'expired' | 'wrong_signer' {
  if (typeof renewalToken !== 'string') return 'expired';
  const pending = pendingLeases.get(renewalToken);
  if (!pending || pending.userId !== userId) return 'expired';
  if (pending.expiresAt <= Date.now()) {
    pendingLeases.delete(renewalToken);
    return 'expired';
  }
  let signer = '';
  try { signer = verifyMessage(pending.stage.leaseSiwe, signature); } catch { /* not the owner's: refused below */ }
  if (signer.toLowerCase() !== pending.stage.ownerAddress.toLowerCase()) return 'wrong_signer';
  pendingLeases.delete(renewalToken);
  return pending.stage;
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
