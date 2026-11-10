// Account deletion from Settings (App Store 5.1.1(v); plan TC-1188 §6, D6).
// POST /api/account/delete needs a cookie session from an OpenKey origin, the
// typed confirmation, and a step-up on this session within five minutes: a
// passkey verification for a user with a step-up passkey, else a
// deletion-purpose email code. Every request here is cookie-only, because the
// API refuses an Authorization header on these routes.
import {
  startAuthentication,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';

export const DELETE_CONFIRMATION = 'DELETE MY ACCOUNT';
export const DELETE_ACCOUNT_PATH = '/dashboard/settings/delete-account';

export type DeletionMethod = 'passkey' | 'email';

export interface DeletionAccount {
  email: string;
  keys: number;
  method: DeletionMethod;
  /** Apple reported that it stopped forwarding mail to this relay address. */
  emailUndeliverable: boolean;
  /** The API serves the passkey step-up on the current session. */
  passkeyStepUpAvailable: boolean;
}

export type DeletionSupport =
  | { supported: true; account: DeletionAccount }
  | { supported: false };

/**
 * Reads `GET /api/account`. The deletion step-up shipped with
 * `user.emailUndeliverable` (TC-1231), so its absence means an API that
 * cannot delete a passkey-less account, and the flow stays hidden.
 * `user.stepUpPasskeys` (TC-1198) comes with the passkey step-up on the
 * current session; before it, a passkey user cannot verify from the web.
 */
function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' ? value as Record<string, unknown> : null;
}

export function parseDeletionSupport(body: unknown): DeletionSupport {
  const user = record(record(body)?.user);
  if (!user || typeof user.email !== 'string' || typeof user.emailUndeliverable !== 'boolean') {
    return { supported: false };
  }
  const counts = record(user._count);
  const passkeys = typeof counts?.passkeys === 'number' ? counts.passkeys : 0;
  const keys = typeof counts?.ethereumKeys === 'number' ? counts.ethereumKeys : 0;
  const stepUpPasskeys = typeof user.stepUpPasskeys === 'number' ? user.stepUpPasskeys : null;
  return {
    supported: true,
    account: {
      email: user.email,
      keys,
      method: (stepUpPasskeys ?? passkeys) > 0 ? 'passkey' : 'email',
      emailUndeliverable: user.emailUndeliverable,
      passkeyStepUpAvailable: stepUpPasskeys !== null,
    },
  };
}

export class DeletionError extends Error {
  constructor(message: string, readonly code: string | null = null, readonly status = 0) {
    super(message);
  }
}

const PASSKEY_REQUIRED = 'passkey_step_up_required';
const EMAIL_REQUIRED = 'email_step_up_required';

/** The method a typed 403 asks for, if any. */
export function requiredMethod(error: unknown): DeletionMethod | null {
  if (!(error instanceof DeletionError)) return null;
  if (error.code === PASSKEY_REQUIRED) return 'passkey';
  if (error.code === EMAIL_REQUIRED) return 'email';
  return null;
}

type Fetch = typeof fetch;

async function post(apiBase: string, path: string, body: unknown, fetchImpl: Fetch): Promise<Response> {
  return fetchImpl(`${apiBase}${path}`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  });
}

async function failure(response: Response, fallback: string): Promise<DeletionError> {
  const body = await response.json().catch(() => null) as { error?: unknown; code?: unknown } | null;
  const code = typeof body?.code === 'string' ? body.code : null;
  if (code === PASSKEY_REQUIRED) return new DeletionError('Verify with your passkey to continue.', code, response.status);
  if (code === EMAIL_REQUIRED) return new DeletionError('Your email code expired. Send a new code to continue.', code, response.status);
  if (response.status === 503) return new DeletionError('OpenKey is busy right now. Try again in a moment.', null, 503);
  if (response.status === 401) return new DeletionError('Your session ended. Sign in again to delete your account.', null, 401);
  return new DeletionError(fallback, null, response.status);
}

export async function loadDeletionSupport(apiBase: string, fetchImpl: Fetch = fetch): Promise<DeletionSupport> {
  const response = await fetchImpl(`${apiBase}/api/account`, { credentials: 'include', headers: { Accept: 'application/json' } });
  if (!response.ok) throw await failure(response, 'Could not load your account. Try again.');
  return parseDeletionSupport(await response.json().catch(() => null));
}

export async function sendDeletionCode(apiBase: string, fetchImpl: Fetch = fetch): Promise<void> {
  const response = await post(apiBase, '/api/account/step-up/email-otp/send', { purpose: 'delete_account' }, fetchImpl);
  if (response.ok) return;
  if (response.status === 503 && !(await response.clone().json().catch(() => null))?.code) {
    throw new DeletionError('OpenKey could not send email right now. Try again later.', null, 503);
  }
  throw await failure(response, 'Could not send a verification code. Try again.');
}

export async function verifyDeletionCode(apiBase: string, code: string, fetchImpl: Fetch = fetch): Promise<void> {
  const response = await post(apiBase, '/api/account/step-up/email-otp/verify', { purpose: 'delete_account', code }, fetchImpl);
  if (response.ok) return;
  if (response.status === 400) throw new DeletionError('That code is wrong or expired. Check the email and try again.', 'invalid_code', 400);
  throw await failure(response, 'Could not verify the code. Try again.');
}

/** The passkey step-up on this cookie session (TC-1198); it mints no new session. */
export async function verifyDeletionPasskey(
  apiBase: string,
  fetchImpl: Fetch = fetch,
  authenticate: typeof startAuthentication = startAuthentication,
): Promise<void> {
  const options = await post(apiBase, '/api/account/step-up/passkey/options', {}, fetchImpl);
  if (options.status === 404) throw new DeletionError(PASSKEY_UNAVAILABLE, 'passkey_step_up_unavailable', 404);
  if (!options.ok) throw await failure(options, 'Could not start passkey verification. Try again.');
  const { challengeToken, options: optionsJSON } = await options.json() as { challengeToken: string; options: PublicKeyCredentialRequestOptionsJSON };
  let assertion: AuthenticationResponseJSON;
  try {
    assertion = await authenticate({ optionsJSON });
  } catch {
    throw new DeletionError('Passkey verification was cancelled. Try again when you are ready.', 'passkey_cancelled');
  }
  const verify = await post(apiBase, '/api/account/step-up/passkey/verify', { challengeToken, response: assertion }, fetchImpl);
  if (verify.ok) return;
  if (verify.status === 400) throw new DeletionError('OpenKey could not verify that passkey. Use a passkey saved for this account.', 'passkey_failed', 400);
  throw await failure(verify, 'Could not verify your passkey. Try again.');
}

export const PASSKEY_UNAVAILABLE =
  "Confirming with a passkey isn't available here yet, so this account can't be deleted from the web right now. Try again later.";

export async function deleteAccount(apiBase: string, fetchImpl: Fetch = fetch): Promise<{ keysDeleted: number }> {
  const response = await post(apiBase, '/api/account/delete', { confirmation: DELETE_CONFIRMATION }, fetchImpl);
  if (!response.ok) throw await failure(response, 'Could not delete your account. Nothing was deleted. Try again.');
  const body = await response.json().catch(() => null) as { success?: unknown; keysDeleted?: unknown } | null;
  if (body?.success !== true) throw new DeletionError('Could not confirm the deletion. Reload to check your account.');
  return { keysDeleted: typeof body.keysDeleted === 'number' ? body.keysDeleted : 0 };
}

/** Plan §6: a relay address Apple no longer forwards to can't receive the code. */
export function relayForwardingMessage(email: string): string {
  return `Apple has stopped forwarding email to ${email}, so your code can't reach you. In your Apple Account settings, open Sign in with Apple, choose OpenKey and turn email forwarding back on, then send a new code.`;
}
