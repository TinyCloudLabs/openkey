import { createHash, randomBytes } from 'node:crypto';
import { SiweMessage } from 'siwe';
import { verifyMessage } from 'ethers';
import { parseApprovalRenewal, type OpenKeyApprovalRequestV1 } from '@tinycloud/share-envelope/links';
import { strictSessionDid, type DeviceRelayEnvelope } from './device-authorization';
import { hasPrivateJwkMember } from './authorization-signing';
import { verifySessionProofClaims } from './native-delegation/session-proof';
import { allocateDelegationCode, delegationClaimHash, type ApprovalCode, type ApprovalCodeDelivery, type ApprovalCodeStore } from '../routes/delegation-codes';
import { logApprovalCodeAllocationFailure, logApprovalCodeCleanupFailure } from '../log';
import type { ApprovalResultRenewal, RenewalStage } from './renewal-lease';

export interface ApprovalRequestRecord {
  id: string;
  bodyCid: string;
  issuer: string;
  request: OpenKeyApprovalRequestV1;
  expiresAt: Date;
  createdAt: Date;
  resultRef: string | null;
  approvedByUserId?: string | null;
  ownerDid?: string | null;
  encryptedResult: string | null;
  delegationExpiresAt?: Date | null;
  resultExpiresAt: Date | null;
  ackId?: string | null;
  acknowledgedAt?: Date | null;
  deniedAt?: Date | null;
  approvingAt?: Date | null;
  /** The renewal lease in progress or done for this request (TC-2933), saved at each step. */
  renewal?: RenewalStage | null;
}

export interface ApprovalRequestStore {
  register(record: ApprovalRequestRecord): Promise<ApprovalRequestRecord>;
  findById(id: string): Promise<ApprovalRequestRecord | null>;
  findByResultRef(ref: string): Promise<ApprovalRequestRecord | null>;
  /**
   * Admits an approval: sets the `approving` marker on a pending, unexpired request with no live marker, and
   * returns the marker it wrote. Null when the request is approved, denied, expired, unknown or already being approved.
   */
  admit(id: string, now: Date): Promise<Date | null>;
  /** Clears the marker, only if it is still this one. */
  release(id: string, marker: Date): Promise<void>;
  /**
   * Saves the result. With the marker from `admit` the save needs that exact marker (a deny or a re-admission replaces it),
   * and a request that expired no more than one lease ago. Without it the request must be unexpired and have no live marker.
   * With `lease`, the node-admitted renewal lease is recorded in the same transaction, only if this save wins.
   */
  approve(id: string, result: { resultRef: string; approvedByUserId: string; ownerDid: string; encryptedResult: string; delegationExpiresAt: Date; resultExpiresAt: Date; lease?: RenewalLeaseRecord }, now: Date, marker?: Date): Promise<boolean>;
  /** Saves the renewal stage while this exact admission marker holds and the request has no result. */
  saveRenewal(id: string, stage: RenewalStage, marker: Date): Promise<boolean>;
  acknowledge(ref: string, ackId: string, now: Date): Promise<ApprovalRequestRecord | null>;
  /** Marks a pending, unexpired request denied. False when it is approved, denied, expired, unknown or being approved. */
  deny(id: string, now: Date): Promise<boolean>;
}

/** The lasting record of a node-admitted owner renewal lease (TC-2933), kept so the owner can see and stop it. */
export interface RenewalLeaseRecord {
  leaseCid: string;
  userId: string;
  /** The OpenKey session that completed the approval. */
  sessionId: string | null;
  approvalRequestId: string;
  ownerDid: string;
  originalCid: string;
  nodeOrigin: string;
  nodeDid: string;
  renewerDid: string;
  leaseLifetimeSeconds: number;
  approvedAt: Date;
  leaseExpiresAt: Date;
}

/** How long an `approving` marker holds off deny and other approvals, so an abandoned one cannot block a request for good. */
export const APPROVAL_CLAIM_LEASE_MS = 30_000;

export class ApprovalResultError extends Error {
  /** `extra` is merged into the JSON error body next to `error` and `code`. */
  constructor(readonly code: string, message: string, readonly status: 400 | 401 | 403 | 404 | 409 | 410 | 503, readonly extra?: Record<string, unknown>) {
    super(message);
  }
}

/**
 * A denied request answers like an expired one: HTTP 410 with the existing `expired_request` code, which
 * every released client already treats as terminal. `status: "denied"` and `deniedAt` tell the clients that
 * know about denial why (TC-2377).
 */
function deniedError(deniedAt: Date): ApprovalResultError {
  return new ApprovalResultError('expired_request', 'Approval request was denied', 410, { status: 'denied', deniedAt: deniedAt.toISOString() });
}

/** Declining needs the complete approval link. The same answer for every way of not having it, and it never names the link. */
export function linkRequiredError(): ApprovalResultError {
  return new ApprovalResultError('link_required', 'Declining needs the complete approval link', 403);
}

/** True while an admitted approval's lease is running. */
export function isApproving(record: Pick<ApprovalRequestRecord, 'approvingAt'>, now: Date): boolean {
  return !!record.approvingAt && record.approvingAt.getTime() > now.getTime() - APPROVAL_CLAIM_LEASE_MS;
}

/** Plain JSON canonicalization is only for comparison; never a replacement for the sealed-byte CID. */
function sameJson(left: unknown, right: unknown): boolean {
  const sorted = (value: unknown): unknown => Array.isArray(value) ? value.map(sorted)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, sorted(item)]))
      : value;
  return JSON.stringify(sorted(left)) === JSON.stringify(sorted(right));
}

export class ApprovalResultService {
  constructor(readonly store: ApprovalRequestStore, private readonly options: {
    apiOrigin: string;
    retentionSeconds: number;
    now?: () => Date;
    codeStore?: ApprovalCodeStore;
  }) {
    if (!Number.isSafeInteger(options.retentionSeconds) || options.retentionSeconds <= 0) {
      throw new Error('Approval result retention must be an explicit positive number of seconds');
    }
    if (new URL(options.apiOrigin).origin !== options.apiOrigin) throw new Error('Approval API origin must be canonical');
  }

  /** `admitted`: the request was admitted in time, so its own deadline is not looked at again; everything else is. */
  async assertDelegationWindow(id: unknown, input: { jwk: unknown; host: unknown; permissions: unknown; expiryMs?: number; signedSiwe?: string }, admitted = false): Promise<ApprovalRequestRecord> {
    const record = typeof id === 'string' ? await this.store.findById(id) : null;
    const now = this.options.now?.() ?? new Date();
    if (record?.deniedAt) throw deniedError(record.deniedAt);
    if (!record || (!admitted && record.expiresAt <= now) || record.resultRef) throw new ApprovalResultError('expired_request', 'Approval request is no longer pending', 410);
    const request = record.request;
    const jwk = input.jwk as JsonWebKey | null;
    if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || jwk.x !== request.targetPublicJwk.x || hasPrivateJwkMember(jwk) ||
      input.host !== request.nodeOrigin || !sameJson(input.permissions, request.permissions)) {
      throw new ApprovalResultError('request_binding', 'Delegation binding does not match the immutable approval request', 400);
    }
    // The requester signed the longest lifetime it will accept; the owner may pick a shorter one.
    if (input.expiryMs !== undefined && input.expiryMs > request.grantLifetimeSeconds * 1000) {
      throw new ApprovalResultError('request_binding', 'Grant lifetime exceeds the immutable approval request', 400);
    }
    if (input.signedSiwe !== undefined) {
      let siwe: SiweMessage;
      try { siwe = new SiweMessage(input.signedSiwe); } catch { throw new ApprovalResultError('invalid_delegation', 'Approval requires a canonical SIWE', 400); }
      const expiry = Date.parse(siwe.expirationTime ?? '');
      if (siwe.prepareMessage() !== input.signedSiwe || siwe.uri !== strictSessionDid(request.targetPublicJwk) || !Number.isFinite(expiry) || expiry <= now.getTime() ||
        expiry > now.getTime() + request.grantLifetimeSeconds * 1000 + 5000) {
        throw new ApprovalResultError('request_binding', 'Signed target or expiry does not match the approval request', 400);
      }
    }
    return record;
  }

  /**
   * Called only by the existing authenticated delegate completion handlers. For a request that signed a
   * renewal request, `renewal` is the owner's choice: finite, or leased with the node-admitted lease, which is
   * also recorded for the owner (with the session that completed the approval).
   */
  async approve(id: string, userId: string, body: { jwk: unknown; host: unknown; permissions: unknown }, delegation: Record<string, unknown>, marker?: Date,
    renewal?: { choice: 'finite' } | { choice: 'leased'; renewal: ApprovalResultRenewal; sessionId: string | null }): Promise<ApprovalCode | null> {
    const signedSiwe = delegation.siwe ?? delegation.signedMessage;
    if (typeof signedSiwe !== 'string' || typeof delegation.signature !== 'string') throw new ApprovalResultError('invalid_delegation', 'Signed delegation proof is required', 400);
    const record = await this.assertDelegationWindow(id, { ...body, signedSiwe }, marker !== undefined);
    if (Boolean(record.request.renewal) !== Boolean(renewal)) {
      throw new ApprovalResultError('request_binding', 'Renewal choice does not match the approval request', 400);
    }
    if (renewal?.choice === 'leased') {
      // The requester's codec refuses a malformed renewal; refuse it here first, before anything is saved.
      try { parseApprovalRenewal(renewal.renewal); } catch { throw new ApprovalResultError('invalid_delegation', 'Renewal lease metadata is invalid', 400); }
    }
    const siwe = new SiweMessage(signedSiwe);
    const ownerDid = `did:pkh:eip155:${siwe.chainId}:${siwe.address}`;
    const jwk = delegation.jwk;
    if (verifyMessage(signedSiwe, delegation.signature).toLowerCase() !== siwe.address.toLowerCase() || delegation.ownerDid !== ownerDid ||
      delegation.verificationMethod !== strictSessionDid(record.request.targetPublicJwk) ||
      !jwk || typeof jwk !== 'object' || !('x' in jwk) || jwk.x !== record.request.targetPublicJwk.x) {
      throw new ApprovalResultError('invalid_delegation', 'Signed owner or target binding is invalid', 400);
    }
    const now = this.options.now?.() ?? new Date();
    const delegationExpiresAt = new Date(siwe.expirationTime!);
    const resultExpiresAt = new Date(Math.min(delegationExpiresAt.getTime(), now.getTime() + this.options.retentionSeconds * 1000));
    const payload = {
      resultVersion: 1,
      requestId: record.id,
      requestDigest: record.bodyCid,
      requesterDid: record.issuer,
      ownerDid,
      targetDid: record.request.targetDid,
      delegationExpiresAt: delegationExpiresAt.toISOString(),
      delegation,
      ...(renewal?.choice === 'leased' ? { renewalChoice: 'leased', renewal: renewal.renewal } : renewal ? { renewalChoice: 'finite' } : {}),
    };
    const recipient = await crypto.subtle.importKey('jwk', record.request.resultEncryptionPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: recipient }, ephemeral.privateKey, 256);
    const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const context = new TextEncoder().encode(record.id);
    const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: context, info: new TextEncoder().encode('openkey-device-relay-v1') }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: context }, key, new TextEncoder().encode(JSON.stringify(payload)));
    const envelope: DeviceRelayEnvelope = { version: 1, algorithm: 'ECDH-P256-A256GCM', ephemeralPublicJwk: await crypto.subtle.exportKey('jwk', ephemeral.publicKey) as DeviceRelayEnvelope['ephemeralPublicJwk'], nonce: Buffer.from(nonce).toString('base64url'), ciphertext: Buffer.from(ciphertext).toString('base64url') };
    const resultRef = randomBytes(24).toString('base64url');
    const lease: RenewalLeaseRecord | undefined = renewal?.choice === 'leased' ? {
      leaseCid: renewal.renewal.receipt.leaseCid,
      userId,
      sessionId: renewal.sessionId,
      approvalRequestId: record.id,
      ownerDid,
      originalCid: renewal.renewal.receipt.originalCid,
      nodeOrigin: record.request.nodeOrigin,
      nodeDid: renewal.renewal.receipt.nodeIdentity.nodeDid,
      renewerDid: renewal.renewal.receipt.nodeIdentity.renewerDid,
      leaseLifetimeSeconds: renewal.renewal.approvedLeaseLifetimeSeconds,
      approvedAt: new Date(renewal.renewal.approvedAt),
      leaseExpiresAt: new Date(renewal.renewal.receipt.leaseExpiresAt),
    } : undefined;
    if (!await this.store.approve(id, { resultRef, approvedByUserId: userId, ownerDid, encryptedResult: JSON.stringify(envelope), delegationExpiresAt, resultExpiresAt, ...(lease ? { lease } : {}) }, this.options.now?.() ?? new Date(), marker)) {
      throw new ApprovalResultError('expired_request', 'Approval request expired or was already approved', 410);
    }
    // Approval is already saved. A delivery failure must not ask the owner to approve twice.
    if (!this.options.codeStore) return null;
    const codeExpiresAt = new Date(Math.min(resultExpiresAt.getTime(), now.getTime() + 5 * 60_000));
    const delivery: ApprovalCodeDelivery = { kind: 'approval-result', requestId: record.id, bodyCid: record.bodyCid, resultRef, expiresAt: codeExpiresAt.toISOString() };
    try {
      const code = await allocateDelegationCode(this.options.codeStore, delivery, codeExpiresAt, now);
      if (!code) return null;
      const latest = await this.store.findById(id);
      if (!latest || latest.ackId || !latest.encryptedResult) {
        await this.options.codeStore.invalidateApproval(resultRef);
        return null;
      }
      return code;
    } catch (error) {
      logApprovalCodeAllocationFailure(record.id, error);
      return null;
    }
  }

  /**
   * Admission: called after the delegation checks and before signing starts. Expiry is decided here, once;
   * a request admitted in time is saved even if its deadline passes while it is signed. Only one approval
   * is admitted at a time, and deny is refused while it is in flight.
   */
  async admit(id: string): Promise<Date> {
    const now = this.options.now?.() ?? new Date();
    const marker = await this.store.admit(id, now);
    if (marker) return marker;
    const record = await this.store.findById(id);
    if (record?.deniedAt) throw deniedError(record.deniedAt);
    if (record && !record.resultRef && record.expiresAt > now && isApproving(record, now)) {
      throw new ApprovalResultError('approval_in_progress', 'Approval request is already being approved.', 409);
    }
    throw new ApprovalResultError('expired_request', 'Approval request is no longer pending', 410);
  }

  /** Gives the admission back after a failed attempt, so deny and a retry need not wait for the lease. */
  async release(id: string, marker: Date): Promise<void> {
    await this.store.release(id, marker);
  }

  /** Saves a renewal step under the caller's admission; refused once the request is settled or re-admitted. */
  async saveRenewal(id: string, stage: RenewalStage, marker: Date): Promise<void> {
    if (!await this.store.saveRenewal(id, stage, marker)) {
      throw new ApprovalResultError('expired_request', 'Approval request expired or was already approved', 410);
    }
  }

  private authenticate(record: ApprovalRequestRecord, action: 'discover' | 'fetch' | 'ack', proof: string | undefined, ref = '', ackId = '', codeBinding?: [string, string]): void {
    const jwk = record.request.targetPublicJwk;
    const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');
    const path = action === 'discover' ? `/api/approval-requests/${record.id}/result` : `/api/approval-results/${ref}/${action}`;
    if (!verifySessionProofClaims(proof, { sessionJwk: jwk, sessionJkt: jkt, htu: this.options.apiOrigin + path, clientId: 'openkey-approval-result-v1', credential: JSON.stringify([action, record.id, record.bodyCid, ref, ackId, ...(codeBinding ?? [])]) }, (this.options.now?.() ?? new Date()).getTime())) {
      throw new ApprovalResultError('invalid_proof', 'Requester proof is invalid', 401);
    }
  }

  async discover(id: string, body: { bodyCid: string; approvalCode?: unknown }, proof: string | undefined, claim?: string): Promise<{ status: 'pending' } | { status: 'approved'; resultRef: string; expiresAt: string }> {
    const record = await this.store.findById(id);
    if (!record) throw new ApprovalResultError('not_found', 'Approval request not found', 404);
    if (record.bodyCid !== body.bodyCid) throw new ApprovalResultError('request_binding', 'Request binding is invalid', 400);
    const code = typeof body.approvalCode === 'string' ? body.approvalCode.trim().toLowerCase() : '';
    const claimHash = delegationClaimHash(claim);
    if (body.approvalCode !== undefined && !claimHash) throw new ApprovalResultError('invalid_claim', 'A saved code claim intent is required', 400);
    this.authenticate(record, 'discover', proof, '', '', body.approvalCode === undefined ? undefined : [
      createHash('sha256').update(code).digest('base64url'), claimHash!,
    ]);
    if (record.deniedAt) throw deniedError(record.deniedAt);
    if (body.approvalCode !== undefined) {
      const now = this.options.now?.() ?? new Date();
      if (record.ackId) throw new ApprovalResultError('acknowledged', 'Approval result was acknowledged', 409);
      if (record.resultRef && record.resultExpiresAt! <= now) throw new ApprovalResultError('expired_result', 'Result retention expired', 410);
      if (!/^[a-z2-7]{4}-[a-z2-7]{4}$/.test(code) || !record.resultRef || !this.options.codeStore ||
        !await this.options.codeStore.claim(code, claimHash!, now, { requestId: record.id, bodyCid: record.bodyCid, resultRef: record.resultRef })) {
        throw new ApprovalResultError('approval_code_unavailable', 'Approval code is unavailable for this saved request', 404);
      }
    }
    if (record.resultRef) {
      if (record.resultExpiresAt! <= (this.options.now?.() ?? new Date())) throw new ApprovalResultError('expired_result', 'Result retention expired', 410);
      return { status: 'approved', resultRef: record.resultRef, expiresAt: record.resultExpiresAt!.toISOString() };
    }
    if (record.expiresAt <= (this.options.now?.() ?? new Date())) throw new ApprovalResultError('expired_request', 'Approval request expired', 410);
    return { status: 'pending' };
  }

  /**
   * Declining refuses this request. Terminal and idempotent; an approved request cannot be declined.
   * Requests carry no owner account, so the capability is the link, as for approving: `link` is the signed
   * header of the link the caller opened (the route re-resolves the full link with its key) and must be
   * this request's, or the caller is refused and the request stays open.
   */
  async deny(id: string, link: { bodyCid: string; issuer: string }): Promise<{ status: 'denied' }> {
    const now = this.options.now?.() ?? new Date();
    const found = await this.store.findById(id);
    if (!found) throw new ApprovalResultError('not_found', 'Approval request not found', 404);
    if (found.bodyCid !== link.bodyCid || found.issuer !== link.issuer) throw linkRequiredError();
    const settled = async (): Promise<{ status: 'denied' }> => {
      const record = await this.store.findById(id);
      if (!record) throw new ApprovalResultError('not_found', 'Approval request not found', 404);
      if (record.deniedAt) return { status: 'denied' };
      if (record.resultRef) throw new ApprovalResultError('already_approved', 'Approval request was already approved', 409);
      if (record.expiresAt > now && isApproving(record, now)) throw new ApprovalResultError('approval_in_progress', 'Approval request is already being approved.', 409);
      throw new ApprovalResultError('expired_request', 'Approval request expired', 410);
    };
    if (!await this.store.deny(id, now)) return settled();
    return { status: 'denied' };
  }

  private async result(ref: string, body: { requestId: string; bodyCid: string }, action: 'fetch' | 'ack', proof: string | undefined, ackId = ''): Promise<ApprovalRequestRecord> {
    const record = await this.store.findByResultRef(ref);
    if (!record) throw new ApprovalResultError('not_found', 'Approval result not found', 404);
    if (record.id !== body.requestId || record.bodyCid !== body.bodyCid) throw new ApprovalResultError('request_binding', 'Result binding is invalid', 400);
    this.authenticate(record, action, proof, ref, ackId);
    if (record.resultExpiresAt! <= (this.options.now?.() ?? new Date())) throw new ApprovalResultError('expired_result', 'Result retention expired', 410);
    return record;
  }

  async fetch(ref: string, body: { requestId: string; bodyCid: string }, proof: string | undefined) {
    const record = await this.result(ref, body, 'fetch', proof);
    if (record.ackId || !record.encryptedResult) throw new ApprovalResultError('acknowledged', 'Approval result was acknowledged', 409);
    return { relay: JSON.parse(record.encryptedResult) as DeviceRelayEnvelope, requestId: record.id, bodyCid: record.bodyCid, resultRef: ref, expiresAt: record.resultExpiresAt!.toISOString() };
  }

  async acknowledge(ref: string, body: { requestId: string; bodyCid: string; ackId: string }, proof: string | undefined) {
    if (typeof body.ackId !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(body.ackId)) throw new ApprovalResultError('invalid_ack', 'A durable ACK intent is required', 400);
    await this.result(ref, body, 'ack', proof, body.ackId);
    const record = await this.store.acknowledge(ref, body.ackId, this.options.now?.() ?? new Date());
    if (!record) throw new ApprovalResultError('ack_conflict', 'Result ACK intent conflicts with the saved ACK', 409);
    try {
      await this.options.codeStore?.invalidateApproval(ref);
    } catch (error) {
      logApprovalCodeCleanupFailure(record.id, error);
      // The durable ACK is authoritative for every collection path. Code expiry
      // bounds optional broker cleanup even when that storage is unavailable.
    }
    return { ackId: record.ackId!, status: 'acknowledged' as const };
  }
}
