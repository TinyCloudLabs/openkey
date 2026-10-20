// TC-1632: server-checked QA exemption from the Turnstile step on new-account
// creation. The secret is the only authority: no email, pattern, or account
// registry decides it. Accepted only on the sign-in/email-otp new-account
// branch, which marks the single-use sign-up token server-side.
import { createHash, timingSafeEqual } from 'node:crypto';

export const QA_REGISTRATION_HEADER = 'x-openkey-qa-registration';

function digest(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

/**
 * True only when the presented value equals the current or previous secret,
 * so a secret can be rotated without a flag day. Both configured secrets are
 * compared on every call, and digests are compared so length does not leak.
 * An unset secret never matches.
 */
export function qaRegistrationAuthorized(presented: string | null, env: NodeJS.ProcessEnv = process.env): boolean {
  if (!presented) return false;
  const candidate = digest(presented);
  let matched = false;
  for (const secret of [env.OPENKEY_QA_REGISTRATION_SECRET, env.OPENKEY_QA_REGISTRATION_SECRET_PREVIOUS]) {
    if (secret && timingSafeEqual(candidate, digest(secret))) matched = true;
  }
  return matched;
}
