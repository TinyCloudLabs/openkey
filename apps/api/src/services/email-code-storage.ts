import { createHmac } from 'node:crypto';

/**
 * Email codes are stored as a keyed hash under the server secret.
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
 * Better Auth sign-in codes are stored as a keyed hash, so the database never holds a usable code. A hash cannot
 * be mailed again, so each resend sends a new code and the earlier one stops working. A stored value from before
 * (plain or encrypted) never matches, and the next send replaces it.
 */
export const signInCodeStorage = {
  hash: async (otp: string) => createHmac('sha256', emailCodeSecret()).update(`openkey-sign-in-code\0${otp}`).digest('hex'),
};

/** The stored form of an account step-up code, bound to its verification identifier. */
export function stepUpCodeDigest(identifier: string, code: string): string {
  return createHmac('sha256', emailCodeSecret()).update(`openkey-step-up-code\0${identifier}\0${code}`).digest('hex');
}
