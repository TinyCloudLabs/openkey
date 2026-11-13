import { randomBytes } from 'node:crypto';
import type { ShareApprovalAccount } from './share-approval-request';
import { ShareApprovalError } from './share-approval';

export interface ShareWindowContext extends ShareApprovalAccount {
  purpose: 'share-create';
  requestId: string;
  origin: string;
  expiresAt: number;
}
type Record = { context: Readonly<ShareWindowContext>; state: 'pending' | 'consumed' | 'cancelled' };

/** Widget attestation under OpenKey's cookie/CSRF boundary, not cryptographic origin proof.
 * Issue and consume must hit one isolate; use an atomic shared store before horizontal scale.
 */
export class ShareWindowContexts {
  private readonly records = new Map<string, Record>();
  constructor(private readonly now: () => number = Date.now) {}

  issue(account: ShareApprovalAccount, requestId: string, observedOrigin: string) {
    const origin = new URL(observedOrigin);
    if (origin.protocol !== 'https:' || origin.origin !== observedOrigin || !requestId || requestId.length > 256) {
      throw new ShareApprovalError('invalid_share_window');
    }
    for (const [token, record] of this.records) if (record.context.expiresAt <= this.now()) this.records.delete(token);
    for (const record of this.records.values()) {
      if (record.context.userId === account.userId && record.context.authSessionId === account.authSessionId &&
        record.context.keyId !== account.keyId) record.state = 'cancelled';
    }
    const owned = [...this.records.values()].filter(record => record.context.userId === account.userId);
    if (owned.length >= 8 || this.records.size >= 10_000) throw new ShareApprovalError('share_window_limit');
    if (owned.some(record => record.context.authSessionId === account.authSessionId && record.context.requestId === requestId)) {
      throw new ShareApprovalError('share_window_already_issued');
    }
    const context = Object.freeze({ ...account, requestId, origin: observedOrigin, purpose: 'share-create' as const, expiresAt: this.now() + 60_000 });
    const token = randomBytes(32).toString('base64url');
    this.records.set(token, { context, state: 'pending' });
    return { token, context };
  }

  read(token: string, account: ShareApprovalAccount, requestId: string): Readonly<ShareWindowContext> {
    const record = this.records.get(token);
    if (!record || record.state !== 'pending' || record.context.expiresAt <= this.now()) throw new ShareApprovalError('share_window_expired');
    if (record.context.requestId !== requestId || record.context.purpose !== 'share-create' ||
      (['userId', 'authSessionId', 'authSessionGeneration', 'keyId', 'keyType', 'address'] as const).some(field => record.context[field] !== account[field])) {
      throw new ShareApprovalError('share_window_binding_mismatch');
    }
    return record.context;
  }

  consume(token: string, account: ShareApprovalAccount, requestId: string) {
    const context = this.read(token, account, requestId);
    this.records.get(token)!.state = 'consumed';
    return context;
  }

  cancel(token: string, account: ShareApprovalAccount, requestId: string): void {
    this.read(token, account, requestId);
    this.records.get(token)!.state = 'cancelled';
  }

  invalidateSession(userId: string, authSessionId: string): void {
    for (const record of this.records.values()) if (record.context.userId === userId && record.context.authSessionId === authSessionId) record.state = 'cancelled';
  }
}
