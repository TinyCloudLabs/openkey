import { createHash, randomBytes } from 'node:crypto';
import { SiweMessage } from 'siwe';
import { verifyMessage } from 'ethers';
import type { OpenKeyApprovalRequestV1 } from '@tinycloud/share-envelope/links';
import { strictSessionDid, type DeviceRelayEnvelope } from './device-authorization';
import { verifySessionProofClaims } from './native-delegation/session-proof';

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
}

export interface ApprovalRequestStore {
  register(record: ApprovalRequestRecord): Promise<ApprovalRequestRecord>;
  findById(id: string): Promise<ApprovalRequestRecord | null>;
  findByResultRef(ref: string): Promise<ApprovalRequestRecord | null>;
  approve(id: string, result: { resultRef: string; approvedByUserId: string; ownerDid: string; encryptedResult: string; delegationExpiresAt: Date; resultExpiresAt: Date }, now: Date): Promise<boolean>;
  acknowledge(ref: string, ackId: string, now: Date): Promise<ApprovalRequestRecord | null>;
}

export class ApprovalResultError extends Error {
  constructor(readonly code: string, message: string, readonly status: 400 | 401 | 404 | 409 | 410 | 503) {
    super(message);
  }
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
  }) {
    if (!Number.isSafeInteger(options.retentionSeconds) || options.retentionSeconds < 60 || options.retentionSeconds > 86400) {
      throw new Error('Approval result retention must be explicitly bounded to 60..86400 seconds');
    }
    if (new URL(options.apiOrigin).origin !== options.apiOrigin) throw new Error('Approval API origin must be canonical');
  }

  async assertDelegationWindow(id: unknown, input: { jwk: unknown; host: unknown; permissions: unknown; expiryMs?: number; signedSiwe?: string }): Promise<ApprovalRequestRecord> {
    const record = typeof id === 'string' ? await this.store.findById(id) : null;
    const now = this.options.now?.() ?? new Date();
    if (!record || record.expiresAt <= now || record.resultRef) throw new ApprovalResultError('expired_request', 'Approval request is no longer pending', 410);
    const request = record.request;
    const jwk = input.jwk as JsonWebKey | null;
    if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || jwk.x !== request.targetPublicJwk.x || 'd' in jwk ||
      input.host !== request.nodeOrigin || !sameJson(input.permissions, request.permissions)) {
      throw new ApprovalResultError('request_binding', 'Delegation binding does not match the immutable approval request', 400);
    }
    if (input.expiryMs !== undefined && input.expiryMs !== request.grantLifetimeSeconds * 1000) {
      throw new ApprovalResultError('request_binding', 'Grant lifetime does not match the immutable approval request', 400);
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

  /** Called only by the existing authenticated delegate completion handlers. */
  async approve(id: string, userId: string, body: { jwk: unknown; host: unknown; permissions: unknown }, delegation: Record<string, unknown>): Promise<void> {
    const signedSiwe = delegation.siwe ?? delegation.signedMessage;
    if (typeof signedSiwe !== 'string' || typeof delegation.signature !== 'string') throw new ApprovalResultError('invalid_delegation', 'Signed delegation proof is required', 400);
    const record = await this.assertDelegationWindow(id, { ...body, signedSiwe });
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
    const payload = { requestId: record.id, bodyCid: record.bodyCid, requesterDid: record.issuer, ownerDid, targetDid: record.request.targetDid, expiresAt: delegationExpiresAt.toISOString(), delegation };
    const recipient = await crypto.subtle.importKey('jwk', record.request.resultEncryptionPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: recipient }, ephemeral.privateKey, 256);
    const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const context = new TextEncoder().encode(record.id);
    const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: context, info: new TextEncoder().encode('openkey-device-relay-v1') }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: context }, key, new TextEncoder().encode(JSON.stringify(payload)));
    const envelope: DeviceRelayEnvelope = { version: 1, algorithm: 'ECDH-P256-A256GCM', ephemeralPublicJwk: await crypto.subtle.exportKey('jwk', ephemeral.publicKey) as DeviceRelayEnvelope['ephemeralPublicJwk'], nonce: Buffer.from(nonce).toString('base64url'), ciphertext: Buffer.from(ciphertext).toString('base64url') };
    if (!await this.store.approve(id, { resultRef: randomBytes(24).toString('base64url'), approvedByUserId: userId, ownerDid, encryptedResult: JSON.stringify(envelope), delegationExpiresAt, resultExpiresAt }, this.options.now?.() ?? new Date())) {
      throw new ApprovalResultError('expired_request', 'Approval request expired or was already approved', 410);
    }
  }

  private authenticate(record: ApprovalRequestRecord, action: 'discover' | 'fetch' | 'ack', proof: string | undefined, ref = '', ackId = ''): void {
    const jwk = record.request.targetPublicJwk;
    const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');
    const path = action === 'discover' ? `/api/approval-requests/${record.id}/result` : `/api/approval-results/${ref}/${action}`;
    if (!verifySessionProofClaims(proof, { sessionJwk: jwk, sessionJkt: jkt, htu: this.options.apiOrigin + path, clientId: 'openkey-approval-result-v1', credential: JSON.stringify([action, record.id, record.bodyCid, ref, ackId]) }, (this.options.now?.() ?? new Date()).getTime())) {
      throw new ApprovalResultError('invalid_proof', 'Requester proof is invalid', 401);
    }
  }

  async discover(id: string, body: { bodyCid: string }, proof: string | undefined): Promise<{ status: 'pending' } | { status: 'approved'; resultRef: string; expiresAt: string }> {
    const record = await this.store.findById(id);
    if (!record) throw new ApprovalResultError('not_found', 'Approval request not found', 404);
    if (record.bodyCid !== body.bodyCid) throw new ApprovalResultError('request_binding', 'Request binding is invalid', 400);
    this.authenticate(record, 'discover', proof);
    if (record.resultRef) {
      if (record.resultExpiresAt! <= (this.options.now?.() ?? new Date())) throw new ApprovalResultError('expired_result', 'Result retention expired', 410);
      return { status: 'approved', resultRef: record.resultRef, expiresAt: record.resultExpiresAt!.toISOString() };
    }
    if (record.expiresAt <= (this.options.now?.() ?? new Date())) throw new ApprovalResultError('expired_request', 'Approval request expired', 410);
    return { status: 'pending' };
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
    return { ackId: record.ackId!, status: 'acknowledged' as const };
  }
}
