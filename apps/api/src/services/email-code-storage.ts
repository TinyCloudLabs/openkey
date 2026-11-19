import { createHmac } from 'node:crypto';
import { symmetricDecrypt, symmetricEncrypt } from 'better-auth/crypto';

/**
 * Email codes are stored encrypted or hashed.
 */
function emailCodeSecret(): string {
  const configured = process.env.BETTER_AUTH_SECRET;
  if (configured) return configured;
  if (process.env.NODE_ENV === 'production' || process.env.TEE_MODE === 'production') {
    throw new Error('BETTER_AUTH_SECRET is required');
  }
  return 'openkey-development-email-code-secret-only';
}

/**
 * Better Auth sign-in codes are encrypted rather than hashed so that a resend
 * inside the five-minute window can mail the same code again (TC-13). A stored
 * value that does not decrypt is treated as no code: it never matches, and the
 * next send replaces it.
 */
export const signInCodeStorage = {
  encrypt: (otp: string) => symmetricEncrypt({ key: emailCodeSecret(), data: otp }),
  async decrypt(stored: string) {
    try {
      return await symmetricDecrypt({ key: emailCodeSecret(), data: stored });
    } catch {
      return '';
    }
  },
};

/** The stored form of an account step-up code, bound to its verification identifier. */
export function stepUpCodeDigest(identifier: string, code: string): string {
  return createHmac('sha256', emailCodeSecret()).update(`openkey-step-up-code\0${identifier}\0${code}`).digest('hex');
}
