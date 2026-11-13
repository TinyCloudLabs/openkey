import { randomBytes } from 'node:crypto';

export interface ShareApprovalBinding {
  userId: string;
  keyId: string;
  ownerDid: string;
  sessionDid: string;
  origin: string;
  sessionExpiresAt: number;
}

export interface MintedShareApproval extends ShareApprovalBinding {
  requestId: string;
  nonce: string;
  shareId: string;
  resource: string;
  action: 'tinycloud.encryption/decrypt';
  expiresAt: number;
}

export class ShareApprovalError extends Error {
  constructor(public readonly code: string) { super(code); }
}

/** Short-lived approval contexts. A restart invalidates outstanding contexts. */
export class ShareApprovals {
  private readonly contexts = new Map<string, Readonly<MintedShareApproval>>();
  constructor(private readonly now: () => number = Date.now) {}

  /** Called only after the route verifies the owner-signed session and widget origin. */
  issue(binding: ShareApprovalBinding): Readonly<MintedShareApproval> {
    const origin = new URL(binding.origin);
    if (origin.protocol !== 'https:' || origin.origin !== binding.origin ||
      !/^did:pkh:eip155:[1-9][0-9]*:0x[0-9a-fA-F]{40}$/.test(binding.ownerDid) ||
      !binding.sessionDid.startsWith('did:key:') || !binding.keyId || !binding.userId ||
      !Number.isFinite(binding.sessionExpiresAt) || binding.sessionExpiresAt <= this.now()) {
      throw new ShareApprovalError('invalid_share_binding');
    }
    for (const [key, record] of this.contexts) {
      if (record.expiresAt <= this.now()) this.contexts.delete(key);
    }
    if ([...this.contexts.values()].filter(record => record.userId === binding.userId).length >= 8) {
      throw new ShareApprovalError('share_approval_limit');
    }
    const shareId = randomBytes(16).toString('hex');
    const record = Object.freeze({
      ...binding,
      requestId: randomBytes(32).toString('base64url'),
      nonce: randomBytes(32).toString('base64url'),
      shareId,
      resource: `urn:tinycloud:encryption:${binding.ownerDid}:default/share/${shareId}`,
      action: 'tinycloud.encryption/decrypt' as const,
      expiresAt: Math.min(this.now() + 60_000, binding.sessionExpiresAt),
    });
    this.contexts.set(record.requestId, record);
    return record;
  }

  read(requestId: string, binding: ShareApprovalBinding): Readonly<MintedShareApproval> {
    const record = this.contexts.get(requestId);
    if (!record || record.expiresAt <= this.now()) throw new ShareApprovalError('share_approval_expired');
    for (const field of ['userId', 'keyId', 'ownerDid', 'sessionDid', 'origin', 'sessionExpiresAt'] as const) {
      if (record[field] !== binding[field]) throw new ShareApprovalError('share_approval_binding_mismatch');
    }
    return record;
  }

  cancel(requestId: string, binding: ShareApprovalBinding): void {
    this.read(requestId, binding);
    this.contexts.delete(requestId);
  }

  /** Atomically spend the context before any asynchronous owner signing. */
  consume(requestId: string, binding: ShareApprovalBinding, nonce: string,
    grants: readonly { resource: string; action: string }[]): Readonly<MintedShareApproval> {
    const record = this.read(requestId, binding);
    if (nonce !== record.nonce || grants.length !== 1 ||
      grants[0]?.resource !== record.resource || grants[0]?.action !== record.action) {
      throw new ShareApprovalError('share_approval_scope_mismatch');
    }
    this.contexts.delete(requestId);
    return record;
  }
}
