import { createHash } from 'node:crypto';
import { ApprovalContinuations, type ApprovalIdentity } from './approval-continuation';

export type SignInIdentity = Omit<ApprovalIdentity, 'purpose' | 'serverIntentDigest'>;

/** Keep sign-in's public identity unchanged; bind its internal UV challenge to its own purpose. */
export class SignInContinuations {
  private readonly store = new ApprovalContinuations();
  private public(identity: SignInIdentity): SignInIdentity {
    const { userId, sessionId, requestId, origin, keyId, keyType, address, chainId } = identity;
    return Object.freeze({ userId, sessionId, requestId, origin, keyId, keyType, address, chainId });
  }
  private bound(identity: SignInIdentity): ApprovalIdentity {
    const fields = this.public(identity);
    const serverIntentDigest = createHash('sha256').update(JSON.stringify([
      fields.userId, fields.sessionId, fields.requestId, fields.origin,
      fields.keyId, fields.keyType, fields.address, fields.chainId,
    ])).digest('hex');
    return { ...fields, purpose: 'tinycloud-signin', serverIntentDigest };
  }
  issue(identity: SignInIdentity, now = Date.now()) { return this.store.issue(this.bound(identity), now); }
  challenge(token: string, identity: SignInIdentity, now = Date.now()) { return this.store.challenge(token, this.bound(identity), now); }
  verified(token: string, identity: SignInIdentity, challenge: string, now = Date.now()) { this.store.verified(token, this.bound(identity), challenge, now); }
  identity(token: string, identity: SignInIdentity, now = Date.now()) { return this.public(this.store.identity(token, this.bound(identity), now)); }
  resume(token: string, identity: SignInIdentity, now = Date.now()) { this.store.resume(token, this.bound(identity), now); }
  resumedIdentity(token: string, identity: SignInIdentity, now = Date.now()) { return this.public(this.store.resumedIdentity(token, this.bound(identity), now)); }
  consume(token: string, identity: SignInIdentity, consume: () => boolean, now = Date.now()) { this.store.consume(token, this.bound(identity), consume, now); }
  cancel(token: string, identity: SignInIdentity, now = Date.now()) { this.store.cancel(token, this.bound(identity), now); }
}
