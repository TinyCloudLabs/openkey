// TC-1632: Cloudflare Turnstile check for new-account creation.
//
// The widget token is verified with Cloudflare's siteverify endpoint before a
// sign-up token is consumed. Only a definite "success" for the sign-up action
// lets an account be created. Anything that stops the check from running
// (no secret configured, network failure, timeout, server-side error, or a
// production setup that cannot be checked safely) is "unavailable": the caller
// pauses registration instead of skipping the check.
import { randomUUID } from 'node:crypto';

export const TURNSTILE_ACTION = 'email-signup';

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const SITEVERIFY_TIMEOUT_MS = 5_000;
// Widget tokens are far shorter than this. Longer input is refused without a request.
const MAX_TOKEN_LENGTH = 2048;

// Cloudflare's published test secrets. They accept or refuse any token, so they
// are only meaningful in isolated QA environments.
const PUBLISHED_TEST_SECRETS: Record<string, true> = {
  '1x0000000000000000000000000000000AA': true,
  '2x0000000000000000000000000000000AA': true,
  '3x0000000000000000000000000000000AA': true,
};

// Cloudflare reports these when this server or Cloudflare cannot run the
// check. They say nothing about the visitor, so they are not a failed check.
const SERVER_SIDE_ERRORS: Record<string, true> = {
  'missing-input-secret': true,
  'invalid-input-secret': true,
  'internal-error': true,
};

export type TurnstileOutcome = 'success' | 'rejected' | 'unavailable';

type SiteverifyBody = { success?: unknown; action?: unknown; hostname?: unknown; 'error-codes'?: unknown };

export function isProductionEnv(env: NodeJS.ProcessEnv): boolean {
  return env.NODE_ENV === 'production' || env.TEE_MODE === 'production';
}

/**
 * The reason Turnstile cannot run safely in this environment, or null when it can.
 * Used at boot to log a configuration problem before the first sign-up needs it.
 */
export function turnstileConfigProblem(env: NodeJS.ProcessEnv = process.env): 'missing_secret' | 'test_secret' | 'missing_hostname' | null {
  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) return 'missing_secret';
  if (!isProductionEnv(env)) return null;
  if (Object.hasOwn(PUBLISHED_TEST_SECRETS, secret)) return 'test_secret';
  if (!env.TURNSTILE_EXPECTED_HOSTNAME) return 'missing_hostname';
  return null;
}

export async function verifyTurnstileToken(
  token: string,
  env: NodeJS.ProcessEnv = process.env,
  remoteIp?: string,
): Promise<TurnstileOutcome> {
  const production = isProductionEnv(env);
  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) return 'unavailable';
  // Production never accepts a published test secret: it would pass any widget token.
  if (production && Object.hasOwn(PUBLISHED_TEST_SECRETS, secret)) return 'unavailable';
  const expectedHostname = env.TURNSTILE_EXPECTED_HOSTNAME;
  // Production must name the hostname it checks. Without it the hostname check is skipped.
  if (production && !expectedHostname) return 'unavailable';
  if (token.length > MAX_TOKEN_LENGTH) return 'rejected';

  const form = new URLSearchParams({ secret, response: token, idempotency_key: randomUUID() });
  if (remoteIp) form.set('remoteip', remoteIp);

  let response: Response;
  try {
    response = await fetch(SITEVERIFY_URL, {
      method: 'POST',
      body: form,
      signal: AbortSignal.timeout(SITEVERIFY_TIMEOUT_MS),
    });
  } catch {
    return 'unavailable';
  }
  if (!response.ok) return 'unavailable';

  let body: SiteverifyBody;
  try {
    body = (await response.json()) as SiteverifyBody;
  } catch {
    return 'unavailable';
  }
  if (!body || typeof body !== 'object') return 'unavailable';

  if (body.success === true) {
    // A missing or different hostname is rejected.
    if (expectedHostname && body.hostname !== expectedHostname) return 'rejected';
    // Production requires the sign-up action. Elsewhere, Cloudflare test keys do not echo `action`, so it is accepted when absent.
    if (production) return body.action === TURNSTILE_ACTION ? 'success' : 'rejected';
    return body.action === undefined || body.action === TURNSTILE_ACTION ? 'success' : 'rejected';
  }
  const errors = Array.isArray(body['error-codes']) ? body['error-codes'] : [];
  if (errors.some((code) => typeof code === 'string' && Object.hasOwn(SERVER_SIDE_ERRORS, code))) return 'unavailable';
  return 'rejected';
}
