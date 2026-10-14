// TC-1114: a verified email code for an address with no OpenKey account does
// not sign in or create anything. The API answers with this code and a
// single-use sign-up token; the account exists only once the user confirms
// by posting that token to SIGN_UP_EMAIL_OTP_PATH.
export const NEW_ACCOUNT_CONFIRMATION_REQUIRED = 'NEW_ACCOUNT_CONFIRMATION_REQUIRED';
export const SIGN_UP_EMAIL_OTP_PATH = '/sign-up/email-otp';

/** The sign-up token from a "new account" answer, or null for any other error. */
export function newAccountSignupToken(error: unknown): string | null {
  if (typeof error !== 'object' || error === null) return null;
  const { code, signupToken } = error as { code?: unknown; signupToken?: unknown };
  return code === NEW_ACCOUNT_CONFIRMATION_REQUIRED && typeof signupToken === 'string' && signupToken
    ? signupToken
    : null;
}
