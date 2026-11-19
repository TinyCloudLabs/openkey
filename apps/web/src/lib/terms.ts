// TC-3232: the required Terms acceptance. The API is the gate and the only source of the release
// (version, effective date, what changed); the web bundle holds nothing but the two document links.
import { DELETE_ACCOUNT_PATH } from './account-deletion';
import { API_BASE } from './auth-client';

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

/** 'Dec 1, 2026' for '2026-12-01'; null for anything else, so no date is shown. */
export function effectiveDate(value: string | null): string | null {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const date = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
}

export async function loadTermsStatus(): Promise<TermsStatus> {
  const response = await fetch(`${API_BASE}/api/account/terms`, { credentials: 'include', headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/**
 * The status when this account must accept before going on, else null. A failed check is null: the
 * API refuses the account's requests anyway, and that refusal brings it back here.
 */
export async function pendingTerms(): Promise<TermsStatus | null> {
  try {
    const status = await loadTermsStatus();
    return status.requiresAcceptance ? status : null;
  } catch {
    return null;
  }
}

/** Records acceptance of `version`. A native sheet names its OAuth client, which the API checks. */
export async function acceptTerms(version: string, nativeClientId?: string | null): Promise<void> {
  const response = await fetch(`${API_BASE}/api/account/terms/accept`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(nativeClientId ? { version, surface: 'native', clientId: nativeClientId } : { version }),
  });
  if (response.status === 409) throw new TermsVersionMismatch();
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

/** Sends the browser to the Terms screen, which brings it back to this page once the account accepts. */
export function sendToTerms(): void {
  const { pathname, search, hash } = window.location;
  window.location.assign(`/auth/terms?returnTo=${encodeURIComponent(pathname + search + hash)}`);
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
