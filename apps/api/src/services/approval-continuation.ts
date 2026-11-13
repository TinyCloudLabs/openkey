import { createHash, randomBytes } from 'node:crypto';

export type ApprovalIdentity = Readonly<{
  userId: string;
  sessionId: string;
  requestId: string;
  origin: string;
  keyId: string;
  keyType: 'MANAGED' | 'EXTERNAL';
  address: string;
  chainId: number;
  purpose: 'tinycloud-signin' | 'share-create';
  serverIntentDigest: string;
}>;

type Pending = { identity: ApprovalIdentity; challenge: string; expiresAt: number; verified: boolean; handedOff: boolean };
const TTL = 5 * 60 * 1000;
const MAX_PENDING = 10_000;

/** Process-local, fail-closed on restart, like ordinary authorization contexts. */
export class ApprovalContinuations {
  private readonly records = new Map<string, Pending>();
  private readonly issuance = new Map<string, { start: number; count: number }>();

  issue(identity: ApprovalIdentity, now = Date.now()): { token: string; challenge: string } {
    for (const [token, record] of this.records) {
      if (record.expiresAt <= now) this.records.delete(token);
    }
    if (this.records.size >= MAX_PENDING) throw new Error('Too many pending sign-ins');
    if (!['tinycloud-signin', 'share-create'].includes(identity.purpose) ||
        !/^[0-9a-f]{64}$/.test(identity.serverIntentDigest)) throw new Error('Invalid approval purpose');
    const origin = new URL(identity.origin);
    if (origin.origin !== identity.origin || !identity.requestId || !identity.sessionId ||
        !identity.userId || !identity.keyId || !identity.address ||
        !Number.isSafeInteger(identity.chainId) || identity.chainId <= 0) {
      throw new Error('Invalid sign-in identity');
    }
    for (const [key, rate] of this.issuance) {
      if (now - rate.start >= 60_000) this.issuance.delete(key);
    }
    const pendingForUser = [...this.records.values()].filter(record => record.identity.userId === identity.userId).length;
    const userBucket = JSON.stringify(['user', identity.userId]);
    const sessionBucket = JSON.stringify(['session', identity.userId, identity.sessionId]);
    if (pendingForUser >= 5 || (this.issuance.get(userBucket)?.count ?? 0) >= 10 ||
        (this.issuance.get(sessionBucket)?.count ?? 0) >= 5) {
      throw new Error('Sign-in issuance limit reached');
    }
    const newBuckets = [userBucket, sessionBucket].filter(bucket => !this.issuance.has(bucket)).length;
    if (this.issuance.size + newBuckets > MAX_PENDING * 2) throw new Error("Too many pending sign-ins");
    for (const bucket of [userBucket, sessionBucket]) {
      const rate = this.issuance.get(bucket) ?? { start: now, count: 0 };
      rate.count++;
      this.issuance.set(bucket, rate);
    }
    const token = randomBytes(32).toString('base64url');
    // The server-selected random nonce and every identity field participate in
    // the WebAuthn challenge; an assertion for another request cannot resume it.
    const challenge = createHash('sha256').update(JSON.stringify([token, identity])).digest('base64url');
    this.records.set(token, { identity: Object.freeze({ ...identity }), challenge, expiresAt: now + TTL, verified: false, handedOff: false });
    return { token, challenge };
  }

  private current(token: string, identity: ApprovalIdentity, now: number): Pending {
    const record = this.records.get(token);
    if (!record || record.expiresAt <= now) {
      this.records.delete(token);
      throw new Error('Sign-in continuation expired or consumed');
    }
    for (const field of Object.keys(record.identity) as (keyof ApprovalIdentity)[]) {
      if (identity[field] !== record.identity[field]) throw new Error('Sign-in identity changed');
    }
    return record;
  }

  challenge(token: string, identity: ApprovalIdentity, now = Date.now()): string {
    const record = this.current(token, identity, now);
    if (record.verified) throw new Error('Sign-in assertion already verified');
    return record.challenge;
  }

  /** Called only after the request-bound WebAuthn assertion verifies with UV. */
  verified(token: string, identity: ApprovalIdentity, challenge: string, now = Date.now()): void {
    const record = this.current(token, identity, now);
    if (record.verified || challenge !== record.challenge) throw new Error('Invalid sign-in assertion');
    record.verified = true;
  }

  identity(token: string, identity: ApprovalIdentity, now = Date.now()): ApprovalIdentity {
    const record = this.current(token, identity, now);
    if (!record.verified) throw new Error('Sign-in requires a fresh passkey assertion');
    return record.identity;
  }

  resume(token: string, identity: ApprovalIdentity, now = Date.now()): void {
    const record = this.current(token, identity, now);
    if (!record.verified || record.handedOff) throw new Error('Sign-in handoff unavailable');
    record.handedOff = true;
    record.expiresAt = Math.min(record.expiresAt, now + 60_000);
  }

  resumedIdentity(token: string, identity: ApprovalIdentity, now = Date.now()): ApprovalIdentity {
    const pinned = this.identity(token, identity, now);
    if (!this.current(token, identity, now).handedOff) throw new Error('Sign-in handoff has not resumed');
    return pinned;
  }

  /** Invoke synchronously with the existing authorization/preview consumption. */
  consume(token: string, identity: ApprovalIdentity, consumeAuthorization: () => boolean, now = Date.now()): void {
    this.resumedIdentity(token, identity, now);
    if (!consumeAuthorization()) throw new Error('Authorization consumption refused');
    this.records.delete(token);
  }

  cancel(token: string, identity: ApprovalIdentity, now = Date.now()): void {
    this.current(token, identity, now);
    this.records.delete(token);
  }
}
