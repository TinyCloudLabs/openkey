// The owner's renewal lease for an approval request (TC-2933). When the owner leaves
// the renewal box ticked, OpenKey signs, as the owner, a lease that lets the node's
// renewer identity renew exactly the grant just approved, and nothing else, until the
// lease ends. The node then renews that grant on its own (spec #322 D1, D12).
//
// The lease has one ability, `tinycloud.delegation/renew` on `urn:cid:<original CID>`,
// and its audience is the renewer the node itself advertises at its own origin; nothing
// the requester sent chooses it. For an approval request, each step is saved on the request before the next network
// call, so a retry reuses the saved grant and lease instead of signing new ones, and the result is only produced once
// the node has admitted the lease. At an app sign-in (`signin-renewal.ts`, `appAdmits`) the lease is only signed and
// returned: nothing is saved, and the app has the node admit it.
import { randomBytes } from 'node:crypto';
import { completeSessionSetup, ensureEip55, parseRecapFromSiwe, prepareSession } from '@tinycloud/node-sdk-wasm';
import { grantIsBroadOnce, parseCapabilityReview, parseSiweFields, renewalEntryVerdict } from '@openkey/capability-review';
import {
  admitOwnerRenewalLease,
  assertRenewalNodeIdentity,
  type RenewalNodeIdentity,
} from '@tinycloud/sdk-core/delegations/renewal';
import { SiweMessage } from 'siwe';
import { SIWE_DOMAIN } from '../routes/delegate-session';
import { strictSessionDid } from './device-authorization';
import { TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS, isKnownTinyCloudActivationHost } from './tinycloud-hosts';

/** Spec D4: a lease lasts at most one year. */
export const MAX_LEASE_SECONDS = 365 * 86_400;
const NODE_CALL_TIMEOUT_MS = 5_000;
const NODE_RESPONSE_MAX_BYTES = 16 * 1024;

/**
 * Leases stay off until owners can see and revoke them (C6): with `OPENKEY_RENEWAL_LEASES=enabled`
 * a renewal request gets the box; otherwise it shows the plain expiry line and is approved finite.
 */
export function renewalLeasesEnabled(): boolean {
  return process.env.OPENKEY_RENEWAL_LEASES === 'enabled';
}

/**
 * The identities a lease may name on the production TinyCloud node (both of its names): the node DID from
 * `OPENKEY_RENEWAL_NODE_DID` and the renewer DID (the lease's audience) from `OPENKEY_RENEWAL_RENEWER_DID`.
 * Without both no production lease is made; a loopback node outside production is not pinned. The node's
 * own answers must match them exactly, so a host in between cannot present another node or another renewer.
 */
export function pinnedRenewalIdentity(host: string): { nodeDid: string; renewerDid: string } | null | undefined {
  if (!TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(host)) return undefined;
  const nodeDid = process.env.OPENKEY_RENEWAL_NODE_DID?.trim();
  const renewerDid = process.env.OPENKEY_RENEWAL_RENEWER_DID?.trim();
  return nodeDid && renewerDid ? { nodeDid, renewerDid } : null;
}

/** `status` 400 and 409 are the caller's; 503 means the lease could not be set up and nothing was approved. */
export class RenewalLeaseError extends Error {
  constructor(readonly code: string, message: string, readonly status: 400 | 409 | 503 = 503) {
    super(message);
    this.name = 'RenewalLeaseError';
  }
}

/** Shown to the owner whenever a ticked renewal could not be set up: nothing is approved. */
export const RENEWAL_FAILED_MESSAGE = "OpenKey couldn't set up renewal. Nothing was approved. Try again.";

/** What renewal at an app sign-in or on an approval request is called in the owner's words. */
export type RenewalSubject = 'sign-in' | 'request';

/**
 * Shown when renewal leases were turned off under an owner who chose renewal. Before anything is signed the box is
 * still on screen, so unticking it approves without renewal; after signing, the sign-in or request can't finish.
 */
export function renewalUnavailableMessage(subject: RenewalSubject, stage: 'before-signing' | 'after-signing'): string {
  if (stage === 'before-signing') return `Renewal isn't available for this ${subject}. Untick it to approve without renewal.`;
  return subject === 'sign-in'
    ? "Renewal stopped being available while you were approving, so this sign-in didn't finish. Sign in again."
    : "Renewal stopped being available while you were approving, so this request didn't finish. Ask the app to send it again.";
}

/**
 * `sensitiveConfirmed`: the owner ticked the box and then confirmed "Renew sensitive access?" (spec D7). A lease on a
 * grant that reaches secrets is refused without it (TC-3821).
 */
export type RenewalChoice = { choice: 'finite' } | { choice: 'leased'; leaseLifetimeSeconds: number; sensitiveConfirmed?: true };

/** The renewal request an approval request signed: its longest lease. */
export interface SignedRenewalRequest {
  version: 1;
  leaseLifetimeSeconds: number;
}

/**
 * The owner's choice, as the approval preview bound it. A request that did not sign a renewal request
 * takes no choice. One that did needs an explicit finite or leased choice while leases are enabled
 * (never inferred from `renewal` or the lifetime); while they are off it shows no box, so it is finite,
 * and a leased choice is refused. A lease longer than the request or one year is refused.
 */
export function parseRenewalChoice(
  value: unknown, signed: SignedRenewalRequest | undefined, enabled = renewalLeasesEnabled(), subject: RenewalSubject = 'request',
): RenewalChoice | null {
  if (!signed) {
    if (value !== undefined) throw new RenewalLeaseError('request_binding', 'This request did not ask for renewal', 400);
    return null;
  }
  if (!enabled && value === undefined) return { choice: 'finite' };
  if (!value || typeof value !== 'object') throw new RenewalLeaseError('request_binding', 'A renewal choice is required', 400);
  const choice = value as Record<string, unknown>;
  if (choice.choice === 'finite' && Object.keys(choice).length === 1) return { choice: 'finite' };
  if (!enabled) throw new RenewalLeaseError('renewal_disabled', renewalUnavailableMessage(subject, 'before-signing'), 400);
  const seconds = choice.leaseLifetimeSeconds;
  const confirmed = choice.sensitiveConfirmed === true;
  if (choice.choice !== 'leased' || Object.keys(choice).length !== (confirmed ? 3 : 2) || typeof seconds !== 'number' || !Number.isSafeInteger(seconds) ||
    seconds <= 0 || seconds > signed.leaseLifetimeSeconds || seconds > MAX_LEASE_SECONDS) {
    throw new RenewalLeaseError('request_binding', 'Renewal choice does not match the approval request', 400);
  }
  return confirmed ? { choice: 'leased', leaseLifetimeSeconds: seconds, sensitiveConfirmed: true } : { choice: 'leased', leaseLifetimeSeconds: seconds };
}

/** Spec D6/D7 (TC-3821): the longest each renewed window of a grant that reaches secrets may last. */
export const SENSITIVE_RENEWAL_WINDOW_SECONDS = 7 * 86_400;

function unreadableGrant(): RenewalLeaseError {
  return new RenewalLeaseError('renewal_refused', "Renewal can't be set up for this approval, because OpenKey couldn't read one of its permissions. Untick renewal and approve without it, or ask the app for a new link.", 400);
}

/**
 * Whether a lease on this grant needs the owner's confirm (TC-3821), by the rule the approval screen shares
 * (`renewalEntryVerdict` in @openkey/capability-review): an encryption permission on a `secrets/` key or prefix, or
 * decrypt on a whole encryption network. Fails closed: a message the node's reader (`parseSiweFields`) rejects, a ReCap
 * that does not parse, or an encryption permission whose resource is not a valid encryption URN, refuses the lease
 * outright. A SIWE with no ReCap grants nothing and needs no confirm.
 */
export function leaseReachesSecrets(siwe: string): boolean {
  if (!parseSiweFields(siwe).ok) throw unreadableGrant();
  let entries: Array<{ service?: string; space: string; path: string; actions: string[] }>;
  try {
    entries = parseRecapFromSiwe(siwe) as typeof entries;
  } catch {
    throw unreadableGrant();
  }
  if (!Array.isArray(entries)) throw unreadableGrant();
  let reaches = false;
  for (const entry of entries) {
    if (!entry || typeof entry.space !== 'string' || typeof entry.path !== 'string' || !Array.isArray(entry.actions) ||
      entry.actions.some((action) => typeof action !== 'string')) {
      throw unreadableGrant();
    }
    const verdict = renewalEntryVerdict(entry);
    if (verdict === 'unreadable') throw unreadableGrant();
    if (verdict === 'confirm') reaches = true;
  }
  return reaches;
}

/**
 * The D7 confirmation and seven-day grant window apply to grants that reach secrets and the one-hour approval tier.
 * The node renews a grant for exactly that window each time: its expiry less its not-before, else its issued-at
 * (tinycloud-node `renewal::period_seconds`). The total lease length stays the owner's choice within what the requester
 * signed.
 */
export function assertLeaseableGrant(siwe: string, sensitiveConfirmed: boolean): void {
  const reachesSecrets = leaseReachesSecrets(siwe);
  const parsed = parseSiweFields(siwe);
  if (!parsed.ok) throw unreadableGrant();
  const { fields } = parsed;

  if (!reachesSecrets) {
    // Use the approval screen's grant model, including resource service and signer ownership.
    const { permissions } = parseCapabilityReview({
      message: siwe,
      signer: { label: 'OpenKey', address: fields.address, chainId: Number(fields.chainId), provenance: 'managed' },
      editable: false,
      metadataTrust: { status: 'unsigned', reason: 'server classification' },
      reason: { text: '', source: 'none' },
      requester: {
        displayName: '', verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none',
        manifestId: null, manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false,
      },
    });
    if (!permissions.some(grantIsBroadOnce)) return;
  }
  if (!sensitiveConfirmed) {
    throw new RenewalLeaseError('renewal_refused', 'Renewing access to your secrets or encrypted data needs your confirmation. Confirm "Renew sensitive access?" to keep renewal, or untick renewal and approve without it.', 400);
  }
  const end = Date.parse(fields.expirationTime ?? '');
  const anchor = Date.parse(fields.notBefore ?? fields.issuedAt);
  if (!Number.isFinite(end) || !Number.isFinite(anchor) || end <= anchor) throw unreadableGrant();
  if (end - anchor > SENSITIVE_RENEWAL_WINDOW_SECONDS * 1000) {
    throw new RenewalLeaseError('renewal_refused', 'Each renewal of access to your secrets or encrypted data lasts at most 7 days. Choose 7 days or less.', 400);
  }
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
 * The renewer the node at `host` advertises, checked against the node's own id. `host` is the approved
 * grant's own node (the request's node origin, which the grant was signed and registered for); the
 * renewer DID comes only from that node's answer, never from the request. In production only the
 * fixed https TinyCloud node names are asked, and the node's DID and its renewer DID must be the pinned
 * ones (`OPENKEY_RENEWAL_NODE_DID`, `OPENKEY_RENEWAL_RENEWER_DID`); loopback is allowed only outside production. No redirects, a short
 * timeout and a small response cap keep this from relaying anywhere else.
 */
export async function discoverRenewalNodeIdentity(host: string, fetchImpl: typeof fetch = fetch): Promise<RenewalNodeIdentity> {
  if (!isKnownTinyCloudActivationHost(host) || new URL(host).origin !== host) {
    throw new RenewalLeaseError('renewal_unavailable', 'Renewal is only set up on known TinyCloud nodes');
  }
  const pinned = pinnedRenewalIdentity(host);
  if (pinned === null) throw new RenewalLeaseError('renewal_unavailable', 'The production node identity is not configured');
  const read = async (path: string): Promise<Record<string, unknown>> => {
    const response = await fetchImpl(`${host}${path}`, { redirect: 'error', signal: AbortSignal.timeout(NODE_CALL_TIMEOUT_MS) });
    if (!response.ok) throw new RenewalLeaseError('renewal_unavailable', `Node ${path} answered ${response.status}`);
    const bytes = await boundedBytes(response);
    let value: unknown = null;
    try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { /* refused below */ }
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new RenewalLeaseError('renewal_unavailable', `Node ${path} is invalid`);
    return value as Record<string, unknown>;
  };
  const [info, keys] = await Promise.all([read('/info'), read('/.well-known/tinycloud/node-keys')]);
  if (typeof info.nodeId !== 'string' || keys.nodeDid !== info.nodeId || typeof keys.renewerDid !== 'string' ||
    (pinned !== undefined && (keys.nodeDid !== pinned.nodeDid || keys.renewerDid !== pinned.renewerDid)) ||
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

async function boundedBytes(response: Response): Promise<Uint8Array> {
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > NODE_RESPONSE_MAX_BYTES) {
      await reader.cancel();
      throw new RenewalLeaseError('renewal_unavailable', 'Node response is too large');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
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
 * `appAdmits`: the app registers the grant and has the node admit the lease itself (an app sign-in), so the node
 * need not hold the grant yet.
 */
export async function prepareRenewalStage(input: {
  userId: string;
  host: string;
  leaseLifetimeSeconds: number;
  delegation: Record<string, unknown>;
  now: Date;
  fetchImpl?: typeof fetch;
  appAdmits?: boolean;
  /** The owner confirmed renewing sensitive access (`RenewalChoice.sensitiveConfirmed`); a grant reaching secrets needs it. */
  sensitiveConfirmed?: boolean;
}): Promise<RenewalStage> {
  const { delegation } = input;
  if (!Number.isSafeInteger(input.leaseLifetimeSeconds) || input.leaseLifetimeSeconds <= 0 || input.leaseLifetimeSeconds > MAX_LEASE_SECONDS) {
    throw new RenewalLeaseError('request_binding', 'Renewal choice does not match the approval request', 400);
  }
  const header = delegation.delegationHeader as { Authorization?: unknown } | undefined;
  const originalCid = delegation.delegationCid;
  const signedSiwe = delegation.siwe;
  if (input.appAdmits !== true && delegation.hostActivated !== true) {
    // OpenKey admits this lease, so the node must already hold the grant.
    throw new RenewalLeaseError('renewal_unavailable', 'The approved grant was not registered with its node');
  }
  if (typeof header?.Authorization !== 'string' || typeof originalCid !== 'string' || typeof signedSiwe !== 'string' ||
    typeof delegation.spaceId !== 'string') {
    throw new RenewalLeaseError('invalid_delegation', 'The approved grant is incomplete', 400);
  }
  // TC-3821: before the node is asked anything or a lease message exists.
  assertLeaseableGrant(signedSiwe, input.sensitiveConfirmed === true);
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
