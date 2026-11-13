import { createHash } from 'node:crypto';
import { getAddress, verifyMessage } from 'ethers';
import { canonicalizeServiceName, isRawRecapEntry, parsePreparedRecap, prepareDelegationSession, type DelegationJwk } from '../routes/delegate-session';
import { ShareApprovals, ShareApprovalError, type MintedShareApproval } from './share-approval';
import type { ShareWindowContext } from './share-window-context';
import { parseShareApprovalIntent, type ShareApprovalIntent } from './share-approval-intent';
import { shareSessionBinding } from './share-approval-session';

export interface ShareApprovalAccount {
  userId: string;
  authSessionId: string;
  authSessionGeneration: string;
  keyId: string;
  address: string;
  keyType: 'MANAGED' | 'EXTERNAL';
}

type Prepared = ReturnType<typeof prepareDelegationSession>['prepared'];
interface Request {
  account: ShareApprovalAccount;
  intent: ShareApprovalIntent;
  minted: Readonly<MintedShareApproval>;
  prepared: Prepared;
  originalSiwe: string;
  intentDigest: string;
}

/** All signed bytes are built here from the server's minted id, never echoed by the app. */
export class ShareApprovalRequests {
  private readonly requests = new Map<string, Request>();
  private readonly approvals: ShareApprovals;
  constructor(private readonly now: () => number = Date.now) { this.approvals = new ShareApprovals(now); }

  prepare(value: unknown, account: ShareApprovalAccount, window: Readonly<ShareWindowContext>,
    consumeWindow: () => Readonly<ShareWindowContext>) {
    const claimed = parseShareApprovalIntent(value);
    if (window.purpose !== 'share-create' || claimed.origin !== window.origin ||
      (['userId', 'authSessionId', 'authSessionGeneration', 'keyId', 'keyType', 'address'] as const).some(field => window[field] !== account[field])) {
      throw new ShareApprovalError('share_window_binding_mismatch');
    }
    const intent = { ...claimed, origin: window.origin };
    if (intent.keyId !== account.keyId) throw new ShareApprovalError('share_approval_binding_mismatch');
    const binding = shareSessionBinding(intent.session, account, intent.origin, this.now());
    const expiresAt = Date.parse(intent.expiresAt);
    if (expiresAt <= this.now() || expiresAt > binding.sessionExpiresAt) throw new ShareApprovalError('invalid_share_expiry');
    for (const [id, record] of this.requests) if (record.minted.expiresAt <= this.now()) this.requests.delete(id);
    if (consumeWindow() !== window) throw new ShareApprovalError('share_window_binding_mismatch');
    const minted = this.approvals.issue(binding);
    const { prepared } = prepareDelegationSession({
      address: getAddress(account.address), chainId: Number(binding.ownerDid.split(':')[3]),
      prefix: 'applications', jwk: intent.session.publicJwk as DelegationJwk,
      permissions: [...intent.permissions, { service: 'tinycloud.encryption', space: 'encryption',
        path: minted.resource, actions: [minted.action] }],
      domain: new URL(intent.origin).host,
      nonce: intent.approvalNonce,
      issuedAt: new Date(this.now()), expiryMs: expiresAt - this.now(),
    });
    const intentDigest = createHash('sha256').update(JSON.stringify([
      'share-create', window.requestId, minted.requestId, minted.nonce, minted.shareId, account.authSessionId, account.authSessionGeneration,
      binding.ownerDid, binding.sessionDid, intent.origin, prepared.siwe,
    ])).digest('hex');
    this.requests.set(minted.requestId, { account: structuredClone(account), intent: Object.freeze(intent), minted, prepared, originalSiwe: prepared.siwe, intentDigest });
    return this.preview(minted.requestId, account);
  }

  private current(requestId: string, account: ShareApprovalAccount): Request {
    const request = this.requests.get(requestId);
    if (!request) throw new ShareApprovalError('share_approval_expired');
    for (const field of ['userId', 'authSessionId', 'authSessionGeneration', 'keyId', 'keyType'] as const) {
      if (request.account[field] !== account[field]) throw new ShareApprovalError('share_approval_binding_mismatch');
    }
    if (getAddress(request.account.address) !== getAddress(account.address)) throw new ShareApprovalError('share_approval_binding_mismatch');
    const binding = shareSessionBinding(request.intent.session, account, request.intent.origin, this.now());
    this.approvals.read(requestId, binding);
    return request;
  }

  preview(requestId: string, account: ShareApprovalAccount) {
    const record = this.current(requestId, account);
    return { purpose: 'share-create' as const, requestId, shareId: record.minted.shareId,
      ownerDid: record.minted.ownerDid, sessionDid: record.minted.sessionDid,
      origin: record.minted.origin, intentDigest: record.intentDigest,
      expiresAt: record.minted.expiresAt, prepared: structuredClone(record.prepared) };
  }

  cancel(requestId: string, account: ShareApprovalAccount): void {
    const record = this.current(requestId, account);
    this.approvals.cancel(requestId, record.minted);
    this.requests.delete(requestId);
  }

  invalidateSession(userId: string, authSessionId: string, keepGeneration?: string): Set<string> {
    const retained = new Set<string>();
    for (const [id, record] of this.requests) {
      if (record.account.userId !== userId || record.account.authSessionId !== authSessionId) continue;
      if (keepGeneration !== undefined && record.account.authSessionGeneration === keepGeneration) { retained.add(id); continue; }
      try { this.approvals.cancel(id, record.minted); } catch { /* already expired */ }
      this.requests.delete(id);
    }
    return retained;
  }

  /** Call only after the same purpose/digest-bound continuation has fresh verified UV. */
  async sign(requestId: string, account: ShareApprovalAccount, intentDigest: string,
    consumeContinuation: () => void, sign: (message: string) => Promise<string>) {
    const record = this.current(requestId, account);
    if (intentDigest !== record.intentDigest) throw new ShareApprovalError('share_approval_binding_mismatch');
    if (record.prepared.siwe !== record.originalSiwe) throw new ShareApprovalError('share_approval_scope_mismatch');
    const allRows = parsePreparedRecap(record.prepared.siwe);
    const encryptionRows = allRows.filter(row => canonicalizeServiceName(row.service) === 'tinycloud.encryption' ||
      row.actions.some(action => action.startsWith('tinycloud.encryption/')));
    if (encryptionRows.length !== 1 || encryptionRows.some(row => !isRawRecapEntry(row) ||
      row.path !== record.minted.resource || row.actions.length !== 1 || row.actions[0] !== record.minted.action)) {
      throw new ShareApprovalError('share_approval_scope_mismatch');
    }
    const rows = encryptionRows.flatMap(row => row.actions.map(action => ({ resource: row.path, action })));
    // Both synchronous consumptions precede the first signing await.
    try {
      consumeContinuation();
      this.approvals.consume(requestId, record.minted, record.minted.nonce, rows);
    } catch (error) {
      try { this.approvals.cancel(requestId, record.minted); } catch { /* expired or already consumed */ }
      this.requests.delete(requestId);
      throw error;
    }
    this.requests.delete(requestId);
    const signature = await sign(record.prepared.siwe);
    if (getAddress(verifyMessage(record.prepared.siwe, signature)) !== getAddress(account.address)) {
      throw new ShareApprovalError('share_signature_mismatch');
    }
    shareSessionBinding(record.intent.session, account, record.intent.origin, this.now());
    if (Date.parse(record.intent.expiresAt) <= this.now()) throw new ShareApprovalError('invalid_share_expiry');
    return { purpose: 'share-create' as const, requestId, shareId: record.minted.shareId,
      ownerDid: record.minted.ownerDid, sessionDid: record.minted.sessionDid,
      origin: record.minted.origin, prepared: structuredClone(record.prepared), signature };
  }
}
