// TC-1632: Cloudflare Turnstile check for new-account creation.
//
// The widget token is verified with Cloudflare's siteverify endpoint before a
// sign-up token is consumed. Only a definite "success" for the sign-up action
// lets an account be created. Anything that stops the check from running
// (no secret configured, network failure, timeout, server-side error) is
// "unavailable": the caller pauses registration instead of skipping the check.
export const TURNSTILE_ACTION = 'email-signup';

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const SITEVERIFY_TIMEOUT_MS = 5_000;

// Cloudflare reports these when this server or Cloudflare cannot run the
// check. They say nothing about the visitor, so they are not a failed check.
const SERVER_SIDE_ERRORS: Record<string, true> = {
  'missing-input-secret': true,
  'invalid-input-secret': true,
  'internal-error': true,
  'bad-request': true,
};

export type TurnstileOutcome = 'success' | 'rejected' | 'unavailable';

type SiteverifyBody = { success?: unknown; action?: unknown; hostname?: unknown; 'error-codes'?: unknown };

export async function verifyTurnstileToken(token: string, env: NodeJS.ProcessEnv = process.env): Promise<TurnstileOutcome> {
  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) return 'unavailable';

  let response: Response;
  try {
    response = await fetch(SITEVERIFY_URL, {
      method: 'POST',
      body: new URLSearchParams({ secret, response: token }),
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
    // Set in production to the public hostname. A missing or different hostname is rejected.
    const expectedHostname = env.TURNSTILE_EXPECTED_HOSTNAME;
    if (expectedHostname && body.hostname !== expectedHostname) return 'rejected';
    // Cloudflare test keys do not echo `action`. When it is reported it must match.
    return body.action === undefined || body.action === TURNSTILE_ACTION ? 'success' : 'rejected';
  }
  const errors = Array.isArray(body['error-codes']) ? body['error-codes'] : [];
  if (errors.some((code) => typeof code === 'string' && Object.hasOwn(SERVER_SIDE_ERRORS, code))) return 'unavailable';
  return 'rejected';
}
