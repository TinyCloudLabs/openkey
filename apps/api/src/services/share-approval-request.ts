import { createHash } from 'node:crypto';
import { getAddress, verifyMessage } from 'ethers';
import { isRawRecapEntry, parsePreparedRecap, prepareDelegationSession, type DelegationJwk } from '../routes/delegate-session';
import { ShareApprovals, ShareApprovalError, type MintedShareApproval } from './share-approval';
import { parseShareApprovalIntent, type ShareApprovalIntent } from './share-approval-intent';
import { shareSessionBinding } from './share-approval-session';

export interface ShareApprovalAccount {
  userId: string;
  authSessionId: string;
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
  intentDigest: string;
}

/** All signed bytes are built here from the server's minted id, never echoed by the app. */
export class ShareApprovalRequests {
  private readonly requests = new Map<string, Request>();
  private readonly approvals: ShareApprovals;
  constructor(private readonly now: () => number = Date.now) { this.approvals = new ShareApprovals(now); }

  prepare(value: unknown, account: ShareApprovalAccount) {
    const intent = parseShareApprovalIntent(value);
    if (intent.keyId !== account.keyId) throw new ShareApprovalError('share_approval_binding_mismatch');
    const binding = shareSessionBinding(intent.session, account, intent.origin, this.now());
    const expiresAt = Date.parse(intent.expiresAt);
    if (expiresAt <= this.now() || expiresAt > binding.sessionExpiresAt) throw new ShareApprovalError('invalid_share_expiry');
    for (const [id, record] of this.requests) if (record.minted.expiresAt <= this.now()) this.requests.delete(id);
    const minted = this.approvals.issue(binding);
    const { prepared } = prepareDelegationSession({
      address: getAddress(account.address), chainId: Number(binding.ownerDid.split(':')[3]),
      prefix: 'applications', jwk: intent.session.publicJwk as DelegationJwk,
      permissions: [...intent.permissions, { service: 'tinycloud.encryption', space: 'encryption',
        path: minted.resource, actions: [minted.action] }],
      domain: new URL(intent.origin).host,
      nonce: createHash('sha256').update(minted.nonce).digest('hex'),
      issuedAt: new Date(this.now()), expiryMs: expiresAt - this.now(),
    });
    const intentDigest = createHash('sha256').update(JSON.stringify([
      'share-create', minted.requestId, minted.nonce, minted.shareId, account.authSessionId,
      binding.ownerDid, binding.sessionDid, intent.origin, prepared.siwe,
    ])).digest('hex');
    this.requests.set(minted.requestId, { account: structuredClone(account), intent, minted, prepared, intentDigest });
    return this.preview(minted.requestId, account);
  }

  private current(requestId: string, account: ShareApprovalAccount): Request {
    const request = this.requests.get(requestId);
    if (!request) throw new ShareApprovalError('share_approval_expired');
    for (const field of ['userId', 'authSessionId', 'keyId', 'keyType'] as const) {
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

  /** Call only after the same purpose/digest-bound continuation has fresh verified UV. */
  async sign(requestId: string, account: ShareApprovalAccount, intentDigest: string,
    consumeContinuation: () => void, sign: (message: string) => Promise<string>) {
    const record = this.current(requestId, account);
    if (intentDigest !== record.intentDigest) throw new ShareApprovalError('share_approval_binding_mismatch');
    const rows = parsePreparedRecap(record.prepared.siwe).filter(isRawRecapEntry)
      .flatMap(row => row.actions.map(action => ({ resource: row.path, action })));
    // Both synchronous consumptions precede the first signing await.
    consumeContinuation();
    this.approvals.consume(requestId, record.minted, record.minted.nonce, rows);
    this.requests.delete(requestId);
    const signature = await sign(record.prepared.siwe);
    if (getAddress(verifyMessage(record.prepared.siwe, signature)) !== getAddress(account.address)) {
      throw new ShareApprovalError('share_signature_mismatch');
    }
    return { purpose: 'share-create' as const, requestId, shareId: record.minted.shareId,
      ownerDid: record.minted.ownerDid, sessionDid: record.minted.sessionDid,
      origin: record.minted.origin, prepared: structuredClone(record.prepared), signature };
  }
}
