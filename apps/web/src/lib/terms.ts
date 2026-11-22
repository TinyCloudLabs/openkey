// TC-3232: the required Terms acceptance. The API is the gate and the only source of the release
// (version, effective date, what changed); the web bundle holds nothing but the two document links.
import { DELETE_ACCOUNT_PATH } from './account-deletion';
import { API_BASE } from './auth-client';
import { getSessionToken, isEmbedContext } from './embed-passkey';

export const TERMS_URL = 'https://tinycloud.xyz/terms';
export const PRIVACY_URL = 'https://tinycloud.xyz/privacy';

/** `GET /api/account/terms`. `version` is null when no release is configured (nothing is required). */
export interface TermsStatus {
  version: string | null;
  /** YYYY-MM-DD the terms take effect. */
  effective: string | null;
  /** One plain line on what changed; shown only to an account re-accepting. */
  whatChanged: string | null;
  privacyChanged: boolean;
  requiresAcceptance: boolean;
  previouslyAccepted: boolean;
}

export class TermsVersionMismatch extends Error {
  constructor() {
    super('terms_version_mismatch');
  }
}

/** The embedded frame's sign-in screen, after Agree found its sign-in more than 10 minutes old. */
export const SIGN_IN_AGAIN_TO_AGREE = 'Sign in again to agree to the Terms. Agreeing here needs a recent sign-in.';

/** The embedded frame's sign-in is too old to stand in for a person agreeing: sign in again, then agree. */
export class TermsSignInAgain extends Error {
  constructor() {
    super('terms_step_up');
  }
}

/** 'Dec 1, 2026' for '2026-12-01'; null for anything else, so no date is shown. */
export function effectiveDate(value: string | null): string | null {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const date = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
}

/**
 * The credential this surface's account calls use: the frame's session token in an embedded frame (third-party
 * cookies are blocked there), the cookie session anywhere else. The same rule as `fetchAPI`.
 */
function withSurfaceCredential(init: RequestInit): RequestInit {
  const token = isEmbedContext() ? getSessionToken() : null;
  if (!token) return { ...init, credentials: 'include' };
  return { ...init, credentials: 'omit', headers: { ...(init.headers as Record<string, string>), Authorization: `Bearer ${token}` } };
}

export async function loadTermsStatus(): Promise<TermsStatus> {
  const response = await fetch(`${API_BASE}/api/account/terms`, withSurfaceCredential({ headers: { Accept: 'application/json' } }));
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/** A Terms check that has no answer by then is a failed check (Try again), never a page held blank. */
export const TERMS_CHECK_TIMEOUT_MS = 8_000;

/** A session read that has no answer by then is a failed check (Try again), never the page. */
export const SESSION_CHECK_TIMEOUT_MS = 10_000;

/**
 * Where the signed-in account stands with the Terms, read from `GET /api/account/terms`:
 *   accepted   - nothing is owed
 *   required   - the account agrees before anything else (`status` is the release to show)
 *   signed-out - the credential no longer signs anyone in
 *   failed     - the answer could not be read in `TERMS_CHECK_TIMEOUT_MS`; never taken to mean "accepted"
 */
export type TermsCheck =
  | { state: 'accepted' }
  | { state: 'required'; status: TermsStatus }
  | { state: 'signed-out' }
  | { state: 'failed' };

export async function checkTerms(fetchImpl: typeof fetch = fetch, timeoutMs = TERMS_CHECK_TIMEOUT_MS): Promise<TermsCheck> {
  // One deadline for the request and its body.
  const signal = AbortSignal.timeout(timeoutMs);
  let response: Response;
  try {
    response = await fetchImpl(`${API_BASE}/api/account/terms`, withSurfaceCredential({ headers: { Accept: 'application/json' }, signal }));
  } catch {
    return { state: 'failed' };
  }
  if (response.status === 401) return { state: 'signed-out' };
  if (!response.ok) return { state: 'failed' };
  const status = await response.json().catch(() => null) as TermsStatus | null;
  if (!status || typeof status !== 'object' || typeof status.requiresAcceptance !== 'boolean') return { state: 'failed' };
  return status.requiresAcceptance ? { state: 'required', status } : { state: 'accepted' };
}

/** The page embedding this frame, as the frame can see it; the API keeps it only as the frame's claim. */
function embeddingOrigin(): string | undefined {
  const ancestors = (window.location as Location & { ancestorOrigins?: DOMStringList }).ancestorOrigins;
  if (ancestors && ancestors.length > 0) return ancestors[0];
  return new URLSearchParams(window.location.search).get('origin') ?? undefined;
}

/**
 * Records acceptance of `version`. A native sheet names its OAuth client, which the API checks. In an embedded
 * frame the session token agrees and the API records the surface itself; a sign-in older than the API allows
 * throws `TermsSignInAgain`.
 */
export async function acceptTerms(version: string, nativeClientId?: string | null): Promise<void> {
  const embedded = isEmbedContext() && getSessionToken() !== null;
  const body = embedded
    ? { version, embedOrigin: embeddingOrigin() }
    : nativeClientId ? { version, surface: 'native', clientId: nativeClientId } : { version };
  const response = await fetch(`${API_BASE}/api/account/terms/accept`, withSurfaceCredential({
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }));
  if (response.status === 409) throw new TermsVersionMismatch();
  if (response.status === 403) {
    const reply = await response.json().catch(() => null);
    if (reply?.error === 'terms_step_up') throw new TermsSignInAgain();
  }
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
}

/** True for the API's refusal of an account that has not accepted the current Terms. */
export function isTermsRequired(status: number, body: unknown): boolean {
  return status === 403 && typeof body === 'object' && body !== null && (body as { error?: unknown }).error === 'terms_required';
}

/**
 * Pages an account uses before it accepts: sign-in, the Terms and their ways out, and deleting the account.
 * A refused call made on one (the header's, say) never sends it to the Terms.
 */
export function isPreTermsPage(pathname: string): boolean {
  return pathname.startsWith('/auth/') || pathname === DELETE_ACCOUNT_PATH;
}

/** The provider-signed authorize query on this page (everything up to and including `sig`), if any. */
export function signedOAuthQuery(search: string): string | undefined {
  const params = new URLSearchParams(search);
  if (!params.has('sig')) return undefined;
  const signed = new URLSearchParams();
  for (const [key, value] of params.entries()) {
    signed.append(key, value);
    if (key === 'sig') break;
  }
  return signed.toString();
}

/** The OAuth client's registered name, for "After you agree, you'll go back to …"; null if unknown. */
export async function oauthClientName(clientId: string): Promise<string | null> {
  const response = await fetch(`${API_BASE}/api/auth/oauth2/public-client?client_id=${encodeURIComponent(clientId)}`, {
    credentials: 'include',
  }).catch(() => null);
  const body = response?.ok ? await response.json().catch(() => null) : null;
  return typeof body?.client_name === 'string' && body.client_name ? body.client_name : null;
}
