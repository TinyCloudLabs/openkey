// TC-1114: a verified email code for an address with no OpenKey account does
// not sign in or create anything. The API answers with this code and a
// single-use sign-up token; the account exists only once the user confirms
// by posting that token to SIGN_UP_EMAIL_OTP_PATH.
export const NEW_ACCOUNT_CONFIRMATION_REQUIRED = 'NEW_ACCOUNT_CONFIRMATION_REQUIRED';
export const SIGN_UP_EMAIL_OTP_PATH = '/sign-up/email-otp';

// TC-1632: codes that leave the sign-up token unspent. The user completes the
// verification check (or waits for it to recover) and confirms again.
const TOKEN_KEPT_CODES: Record<string, true> = {
  TURNSTILE_REQUIRED: true,
  TURNSTILE_FAILED: true,
  REGISTRATION_PAUSED: true,
};

/** The sign-up token from a "new account" answer, or null for any other error. */
export function newAccountSignupToken(error: unknown): string | null {
  if (typeof error !== 'object' || error === null) return null;
  const { code, signupToken } = error as { code?: unknown; signupToken?: unknown };
  return code === NEW_ACCOUNT_CONFIRMATION_REQUIRED && typeof signupToken === 'string' && signupToken
    ? signupToken
    : null;
}

/**
 * TC-1632: whether the new-account answer requires the verification check.
 * Only an explicit `turnstileRequired: false` (valid QA registration secret)
 * skips it; any other value keeps the check.
 */
export function newAccountNeedsChallenge(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return true;
  return (error as { turnstileRequired?: unknown }).turnstileRequired !== false;
}

/** TC-1632: true when a failed confirmation leaves the sign-up token usable. */
export function keepsSignupToken(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const { code } = error as { code?: unknown };
  return typeof code === 'string' && TOKEN_KEPT_CODES[code] === true;
}
