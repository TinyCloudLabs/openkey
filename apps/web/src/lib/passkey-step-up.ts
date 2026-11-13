// TC-1198: adding or removing a passkey needs a fresh step-up on this session:
// an email code for that purpose, or a verification by an existing passkey that
// counts for step-up. The API refuses a session-only change with a typed 403
// that lists the methods it accepts; an API without TC-1198 never sends it, so
// the prompt appears only where the server supports it.
import { startAuthentication, type PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser';

const API_URL = import.meta.env.VITE_API_URL || '';

export type PasskeyStepUpPurpose = 'passkey_register' | 'passkey_remove';
export type PasskeyStepUpMethod = 'passkey' | 'email';

/** The step-up methods a refused passkey change accepts, or null when the error is not a step-up refusal. */
export function passkeyStepUpMethods(error: unknown): PasskeyStepUpMethod[] | null {
  if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'PASSKEY_STEP_UP_REQUIRED') return null;
  const methods = 'methods' in error && Array.isArray(error.methods) ? error.methods : [];
  return methods.filter((method): method is PasskeyStepUpMethod => method === 'passkey' || method === 'email');
}

// Cookie session only: the API refuses step-up requests that carry a bearer token.
function stepUpRequest(path: string, body: unknown): Promise<Response> {
  return fetch(`${API_URL}/api/account/step-up/${path}`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export async function sendPasskeyStepUpCode(purpose: PasskeyStepUpPurpose): Promise<void> {
  const response = await stepUpRequest('email-otp/send', { purpose });
  if (!response.ok) throw new Error("Couldn't send a verification code. Try again.");
}

export async function verifyPasskeyStepUpCode(purpose: PasskeyStepUpPurpose, code: string): Promise<void> {
  const response = await stepUpRequest('email-otp/verify', { purpose, code });
  if (!response.ok) throw new Error('Incorrect or expired code. Check the email and try again.');
}

export async function verifyWithExistingPasskey(): Promise<void> {
  const options = await stepUpRequest('passkey/options', {});
  if (!options.ok) throw new Error('No passkey on this account can confirm this change. Use an email code instead.');
  const { challengeToken, options: optionsJSON } = await options.json() as {
    challengeToken: string;
    options: PublicKeyCredentialRequestOptionsJSON;
  };
  const response = await startAuthentication({ optionsJSON });
  const verified = await stepUpRequest('passkey/verify', { challengeToken, response });
  if (verified.ok) return;
  const body = await verified.json().catch(() => null) as { code?: string } | null;
  throw new Error(body?.code === 'passkey_not_step_up_capable'
    ? "That passkey was added without a verification step, so it can't confirm this change. Use another passkey or an email code."
    : 'Passkey verification failed. Try again.');
}
