import { createHash, randomBytes } from 'node:crypto';

export type SignInIdentity = Readonly<{
  userId: string;
  sessionId: string;
  requestId: string;
  origin: string;
  keyId: string;
  keyType: 'MANAGED' | 'EXTERNAL';
  address: string;
  chainId: number;
}>;

type Pending = { identity: SignInIdentity; challenge: string; expiresAt: number; verified: boolean };
const TTL = 5 * 60 * 1000;

/** Process-local, fail-closed on restart, like ordinary authorization contexts. */
export class SignInContinuations {
  private readonly records = new Map<string, Pending>();

  issue(identity: SignInIdentity, now = Date.now()): { token: string; challenge: string } {
    for (const [token, record] of this.records) {
      if (record.expiresAt <= now) this.records.delete(token);
    }
    if (this.records.size >= 10_000) throw new Error('Too many pending sign-ins');
    const origin = new URL(identity.origin);
    if (origin.origin !== identity.origin || !identity.requestId || !identity.sessionId ||
        !identity.userId || !identity.keyId || !identity.address ||
        !Number.isSafeInteger(identity.chainId) || identity.chainId <= 0) {
      throw new Error('Invalid sign-in identity');
    }
    const token = randomBytes(32).toString('base64url');
    // The server-selected random nonce and every identity field participate in
    // the WebAuthn challenge; an assertion for another request cannot resume it.
    const challenge = createHash('sha256').update(JSON.stringify([token, identity])).digest('base64url');
    this.records.set(token, { identity: Object.freeze({ ...identity }), challenge, expiresAt: now + TTL, verified: false });
    return { token, challenge };
  }

  private current(token: string, identity: SignInIdentity, now: number): Pending {
    const record = this.records.get(token);
    if (!record || record.expiresAt <= now) {
      this.records.delete(token);
      throw new Error('Sign-in continuation expired or consumed');
    }
    for (const field of Object.keys(record.identity) as (keyof SignInIdentity)[]) {
      if (identity[field] !== record.identity[field]) throw new Error('Sign-in identity changed');
    }
    return record;
  }

  challenge(token: string, identity: SignInIdentity, now = Date.now()): string {
    const record = this.current(token, identity, now);
    if (record.verified) throw new Error('Sign-in assertion already verified');
    return record.challenge;
  }

  /** Called only after the request-bound WebAuthn assertion verifies with UV. */
  verified(token: string, identity: SignInIdentity, challenge: string, now = Date.now()): void {
    const record = this.current(token, identity, now);
    if (record.verified || challenge !== record.challenge) throw new Error('Invalid sign-in assertion');
    record.verified = true;
  }

  identity(token: string, identity: SignInIdentity, now = Date.now()): SignInIdentity {
    const record = this.current(token, identity, now);
    if (!record.verified) throw new Error('Sign-in requires a fresh passkey assertion');
    return record.identity;
  }

  /** Invoke synchronously with the existing authorization/preview consumption. */
  consume(token: string, identity: SignInIdentity, consumeAuthorization: () => boolean, now = Date.now()): void {
    this.identity(token, identity, now);
    if (!consumeAuthorization()) throw new Error('Authorization consumption refused');
    this.records.delete(token);
  }

  cancel(token: string, identity: SignInIdentity, now = Date.now()): void {
    this.current(token, identity, now);
    this.records.delete(token);
  }
}
