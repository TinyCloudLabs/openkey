// TC-1632: server-checked QA exemption from the Turnstile step on new-account
// creation. Both must hold: the request presents the configured QA secret in
// the header, and the new account's email matches a QA-eligible pattern in
// config/test-accounts.json. The secret is the authority; a pattern never
// exempts an account by itself. Accepted only on the sign-in/email-otp
// new-account branch, which marks the single-use sign-up token server-side.
import { createHash, timingSafeEqual } from 'node:crypto';
import TEST_ACCOUNTS from '../../config/test-accounts.json';

export const QA_REGISTRATION_HEADER = 'x-openkey-qa-registration';
// 32 random bytes, base64url-encoded. Shorter values are treated as unset.
export const QA_SECRET_MIN_LENGTH = 43;

const QA_ELIGIBLE_PATTERNS: RegExp[] = TEST_ACCOUNTS.patterns
  .filter((pattern) => pattern.qaEligible)
  .map((pattern) => new RegExp(pattern.regex));

function digest(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

function tooShort(value: string | undefined): boolean {
  return value !== undefined && value !== '' && value.length < QA_SECRET_MIN_LENGTH;
}

/** True when a configured QA secret is shorter than the minimum. Such a secret is ignored. */
export function qaRegistrationSecretTooShort(env: NodeJS.ProcessEnv = process.env): boolean {
  return tooShort(env.OPENKEY_QA_REGISTRATION_SECRET) || tooShort(env.OPENKEY_QA_REGISTRATION_SECRET_PREVIOUS);
}

/**
 * True only when the presented value equals the current or previous secret,
 * so a secret can be rotated without a flag day. Both configured secrets are
 * compared on every call, and digests are compared so length does not leak.
 * An unset or too-short secret never matches.
 */
export function qaRegistrationAuthorized(presented: string | null, env: NodeJS.ProcessEnv = process.env): boolean {
  if (!presented) return false;
  const candidate = digest(presented);
  let matched = false;
  for (const secret of [env.OPENKEY_QA_REGISTRATION_SECRET, env.OPENKEY_QA_REGISTRATION_SECRET_PREVIOUS]) {
    if (secret && secret.length >= QA_SECRET_MIN_LENGTH && timingSafeEqual(candidate, digest(secret))) matched = true;
  }
  return matched;
}

/** True when the email matches a QA-eligible registry pattern. Only meaningful together with the secret. */
export function qaEligibleEmail(email: string): boolean {
  const normalized = email.toLowerCase();
  return QA_ELIGIBLE_PATTERNS.some((pattern) => pattern.test(normalized));
}
