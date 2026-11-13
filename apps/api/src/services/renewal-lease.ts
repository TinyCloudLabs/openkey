// The owner's renewal lease for an approval request (TC-2933). When the owner leaves
// the renewal box ticked, OpenKey signs, as the owner, a lease that lets the node's
// renewer identity renew exactly the grant just approved, and nothing else, until the
// lease ends. The node then renews that grant on its own (spec #322 D1, D12).
//
// The lease has one ability, `tinycloud.delegation/renew` on `urn:cid:<original CID>`,
// and its audience is the renewer the node itself advertises at its own origin; nothing
// the requester sent chooses it. Each step is saved on the approval request before the
// next network call, so a retry reuses the saved grant and lease instead of signing new
// ones, and the result is only produced once the node has admitted the lease.
import { randomBytes } from 'node:crypto';
import { completeSessionSetup, ensureEip55, prepareSession } from '@tinycloud/node-sdk-wasm';
import {
  admitOwnerRenewalLease,
  assertRenewalNodeIdentity,
  type RenewalNodeIdentity,
} from '@tinycloud/sdk-core/delegations/renewal';
import { SiweMessage } from 'siwe';
import { SIWE_DOMAIN } from '../routes/delegate-session';
import { strictSessionDid } from './device-authorization';
import { isKnownTinyCloudActivationHost } from './tinycloud-hosts';

/** Spec D4: a lease lasts at most one year. */
export const MAX_LEASE_SECONDS = 365 * 86_400;
const NODE_CALL_TIMEOUT_MS = 5_000;

/** `status` 400 and 409 are the caller's; 503 means the lease could not be set up and nothing was approved. */
export class RenewalLeaseError extends Error {
  constructor(readonly code: string, message: string, readonly status: 400 | 409 | 503 = 503) {
    super(message);
    this.name = 'RenewalLeaseError';
  }
}

/** Shown to the owner whenever a ticked renewal could not be set up: nothing is approved. */
export const RENEWAL_FAILED_MESSAGE = "OpenKey couldn't set up renewal. Nothing was approved. Try again.";

export type RenewalChoice = { choice: 'finite' } | { choice: 'leased'; leaseLifetimeSeconds: number };

/** The renewal request an approval request signed: its longest lease. */
export interface SignedRenewalRequest {
  version: 1;
  leaseLifetimeSeconds: number;
}

/**
 * The owner's choice from the approval body. A request that signed a renewal request
 * needs an explicit choice (finite or leased, never inferred); one that did not may not
 * carry one. A lease longer than the request or one year is refused.
 */
export function parseRenewalChoice(value: unknown, signed: SignedRenewalRequest | undefined): RenewalChoice | null {
  if (!signed) {
    if (value !== undefined) throw new RenewalLeaseError('request_binding', 'This request did not ask for renewal', 400);
    return null;
  }
  if (!value || typeof value !== 'object') throw new RenewalLeaseError('request_binding', 'A renewal choice is required', 400);
  const choice = value as Record<string, unknown>;
  if (choice.choice === 'finite' && Object.keys(choice).length === 1) return { choice: 'finite' };
  const seconds = choice.leaseLifetimeSeconds;
  if (choice.choice !== 'leased' || Object.keys(choice).length !== 2 || typeof seconds !== 'number' || !Number.isSafeInteger(seconds) ||
    seconds <= 0 || seconds > signed.leaseLifetimeSeconds || seconds > MAX_LEASE_SECONDS) {
    throw new RenewalLeaseError('request_binding', 'Renewal choice does not match the approval request', 400);
  }
  return { choice: 'leased', leaseLifetimeSeconds: seconds };
}

/** Saved on the approval request (its `renewal` column) at each step; never holds a private key. */
export interface RenewalStage {
  version: 1;
  userId: string;
  approvedAt: string;
  approvedLeaseLifetimeSeconds: number;
  leaseExpiresAt: string;
  nodeIdentity: RenewalNodeIdentity;
  /** The approved grant, exactly as it goes into the result. */
  delegation: Record<string, unknown>;
  originalCid: string;
  originalAuthorization: string;
  ownerAddress: string;
  chainId: number;
  spaceId: string;
  leaseNonce: string;
  leaseSiwe: string;
  leaseAuthorization?: string;
  leaseCid?: string;
}

/** The `renewal` field of an approval result (js-sdk approval-renewal codec). */
export interface ApprovalResultRenewal {
  version: 1;
  approvedLeaseLifetimeSeconds: number;
  approvedAt: string;
  receipt: {
    originalCid: string;
    leaseCid: string;
    leaseAuthorization: string;
    leaseExpiresAt: string;
    leaseGeneration: 1;
    nodeIdentity: RenewalNodeIdentity;
  };
}

/**
 * The renewer the node at `host` advertises, checked against the node's own id.
 * Only the request's canonical node origin is ever asked (C2).
 */
export async function discoverRenewalNodeIdentity(host: string, fetchImpl: typeof fetch = fetch): Promise<RenewalNodeIdentity> {
  if (!isKnownTinyCloudActivationHost(host) || new URL(host).origin !== host) {
    throw new RenewalLeaseError('renewal_unavailable', 'Renewal is only set up on known TinyCloud nodes');
  }
  const read = async (path: string): Promise<Record<string, unknown>> => {
    const response = await fetchImpl(`${host}${path}`, { redirect: 'error', signal: AbortSignal.timeout(NODE_CALL_TIMEOUT_MS) });
    if (!response.ok) throw new RenewalLeaseError('renewal_unavailable', `Node ${path} answered ${response.status}`);
    const value: unknown = await response.json();
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new RenewalLeaseError('renewal_unavailable', `Node ${path} is invalid`);
    return value as Record<string, unknown>;
  };
  const [info, keys] = await Promise.all([read('/info'), read('/.well-known/tinycloud/node-keys')]);
  if (typeof info.nodeId !== 'string' || keys.nodeDid !== info.nodeId || typeof keys.renewerDid !== 'string' ||
    typeof keys.renewerPublicKey !== 'string' || !Number.isSafeInteger(keys.renewerEpoch) || (keys.renewerEpoch as number) < 0) {
    throw new RenewalLeaseError('renewal_unavailable', 'Node renewal identity is invalid');
  }
  const identity: RenewalNodeIdentity = {
    nodeDid: keys.nodeDid,
    renewerDid: keys.renewerDid,
    renewerPublicKey: keys.renewerPublicKey,
    renewerEpoch: keys.renewerEpoch as number,
  };
  assertRenewalNodeIdentity(identity);
  return identity;
}

function leaseSiwe(stage: Pick<RenewalStage, 'originalCid' | 'ownerAddress' | 'chainId' | 'spaceId' | 'nodeIdentity' | 'leaseNonce' | 'approvedAt' | 'leaseExpiresAt'>) {
  // The same inputs always give the same message, so the bytes the owner signs can be rebuilt instead of stored.
  return prepareSession({
    abilities: {},
    rawAbilities: { [`urn:cid:${stage.originalCid}`]: ['tinycloud.delegation/renew'] },
    address: ensureEip55(stage.ownerAddress),
    chainId: stage.chainId,
    domain: SIWE_DOMAIN,
    spaceId: stage.spaceId,
    delegateUri: stage.nodeIdentity.renewerDid,
    nonce: stage.leaseNonce,
    issuedAt: stage.approvedAt,
    expirationTime: stage.leaseExpiresAt,
  });
}

/**
 * The first stage for an approved grant: server time, the lease end and the lease
 * message, before anything is signed. `delegation` is the grant as the result carries it.
 */
export async function prepareRenewalStage(input: {
  userId: string;
  host: string;
  leaseLifetimeSeconds: number;
  delegation: Record<string, unknown>;
  now: Date;
  fetchImpl?: typeof fetch;
}): Promise<RenewalStage> {
  const { delegation } = input;
  const header = delegation.delegationHeader as { Authorization?: unknown } | undefined;
  const originalCid = delegation.delegationCid;
  const signedSiwe = delegation.siwe;
  if (delegation.hostActivated !== true) {
    // The node must already hold the grant before it can admit a lease for it.
    throw new RenewalLeaseError('renewal_unavailable', 'The approved grant was not registered with its node');
  }
  if (typeof header?.Authorization !== 'string' || typeof originalCid !== 'string' || typeof signedSiwe !== 'string' ||
    typeof delegation.spaceId !== 'string') {
    throw new RenewalLeaseError('invalid_delegation', 'The approved grant is incomplete', 400);
  }
  const siwe = new SiweMessage(signedSiwe);
  const nodeIdentity = await discoverRenewalNodeIdentity(input.host, input.fetchImpl);
  // Whole seconds so approvedAt + lifetime is exactly the signed end at millisecond precision.
  const approvedAt = new Date(Math.floor(input.now.getTime() / 1000) * 1000);
  const stage: RenewalStage = {
    version: 1,
    userId: input.userId,
    approvedAt: approvedAt.toISOString(),
    approvedLeaseLifetimeSeconds: input.leaseLifetimeSeconds,
    leaseExpiresAt: new Date(approvedAt.getTime() + input.leaseLifetimeSeconds * 1000).toISOString(),
    nodeIdentity,
    delegation,
    originalCid,
    originalAuthorization: header.Authorization.replace(/^Bearer\s+/i, ''),
    ownerAddress: siwe.address,
    chainId: siwe.chainId,
    spaceId: delegation.spaceId,
    leaseNonce: randomBytes(12).toString('hex'),
    leaseSiwe: '',
  };
  stage.leaseSiwe = leaseSiwe(stage).siwe;
  return stage;
}

/** Puts the owner's signature on the saved lease message; the message is rebuilt and must match byte for byte. */
export function signLease(stage: RenewalStage, signature: string): RenewalStage {
  const prepared = leaseSiwe(stage);
  if (prepared.siwe !== stage.leaseSiwe) throw new RenewalLeaseError('lease_mismatch', 'Saved renewal lease changed', 409);
  const session = completeSessionSetup({ ...prepared, signature });
  return {
    ...stage,
    leaseAuthorization: String(session.delegationHeader.Authorization).replace(/^Bearer\s+/i, ''),
    leaseCid: session.delegationCid,
  };
}

/** Sends the saved, signed lease to the node. Replays the same bytes on retry; never signs. */
export async function admitLease(stage: RenewalStage, request: { nodeOrigin: string; targetPublicJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string } }): Promise<ApprovalResultRenewal> {
  if (!stage.leaseAuthorization || !stage.leaseCid) throw new RenewalLeaseError('lease_unsigned', 'Renewal lease is not signed', 409);
  const receipt = await admitOwnerRenewalLease({
    host: request.nodeOrigin,
    originalAuthorization: stage.originalAuthorization,
    originalCid: stage.originalCid,
    ownerDid: `did:pkh:eip155:${stage.chainId}:${stage.ownerAddress}`,
    agentDid: strictSessionDid(request.targetPublicJwk),
    spaceId: stage.spaceId,
    nodeIdentity: stage.nodeIdentity,
    leaseAuthorization: stage.leaseAuthorization,
    leaseCid: stage.leaseCid,
    leaseExpiresAt: stage.leaseExpiresAt,
    signal: AbortSignal.timeout(NODE_CALL_TIMEOUT_MS),
  });
  return {
    version: 1,
    approvedLeaseLifetimeSeconds: stage.approvedLeaseLifetimeSeconds,
    approvedAt: stage.approvedAt,
    receipt: { ...receipt, nodeIdentity: { ...receipt.nodeIdentity } },
  };
}
