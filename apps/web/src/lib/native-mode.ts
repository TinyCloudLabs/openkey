import { safeOAuthAuthorizeQuery } from './auth-flow';
import { API_BASE } from './auth-client';
import { safeExternalHttpUrl } from './safe-oauth-url';
import { parseHexColor } from './native-theme';

export type NativeLoginMethod = 'email' | 'passkey' | 'google' | 'apple';
export type NativeSocialProvider = Extract<NativeLoginMethod, 'google' | 'apple'>;

const LOGIN_METHODS: readonly NativeLoginMethod[] = ['email', 'passkey', 'google', 'apple'];
const SOCIAL_PROVIDERS: readonly NativeSocialProvider[] = ['google', 'apple'];

/** Marker on a social error return; its value is the provider that failed. */
export const NATIVE_SOCIAL_ERROR_PARAM = 'native_social_error';

/**
 * Why a native social sign-in came back to the login page. `new_account` and
 * `account_exists` carry the API's single-use continuation; everything else
 * is shown as a message on the email step.
 */
export type NativeSocialErrorCode =
  | 'new_account'
  | 'account_exists'
  | 'apple_email_required'
  | 'account_not_linked'
  | 'cancelled'
  | 'failed';

export interface NativeSocialError {
  /** Null when the return does not name a known provider. */
  provider: NativeSocialProvider | null;
  code: NativeSocialErrorCode;
  /** Non-null only for `new_account` and `account_exists`. */
  continuation: string | null;
}

export interface NativeSignIn {
  requestId: string;
  clientId: string;
  /** The signed authorize query, exactly as the API issued it. */
  signedQuery: string;
  method: NativeLoginMethod | null;
  hint: string | null;
  socialError: NativeSocialError | null;
}

export function socialProviderLabel(provider: NativeSocialProvider): 'Google' | 'Apple' {
  return provider === 'google' ? 'Google' : 'Apple';
}

// The API's continuation is 32 random bytes, base64url.
const CONTINUATION = /^[A-Za-z0-9_-]{43}$/;

/** Null unless the page URL carries the social error marker. */
export function nativeSocialError(searchParams: URLSearchParams): NativeSocialError | null {
  const marker = searchParams.get(NATIVE_SOCIAL_ERROR_PARAM);
  if (marker === null) return null;
  const provider = SOCIAL_PROVIDERS.find((candidate) => candidate === marker) ?? null;
  const error = searchParams.get('error');
  const token = searchParams.get('continuation');
  if (error === 'new_account' || error === 'account_exists') {
    return token && CONTINUATION.test(token)
      ? { provider, code: error, continuation: token }
      : { provider, code: 'failed', continuation: null };
  }
  const code: NativeSocialErrorCode = error === 'access_denied' || error === 'user_cancelled_authorize' ? 'cancelled'
    : error === 'account_not_linked' ? 'account_not_linked'
    : error === 'apple_email_required' && provider === 'apple' ? 'apple_email_required'
    : 'failed';
  return { provider, code, continuation: null };
}

/** Copy for a social return that lands on the email step. */
export function nativeSocialErrorMessage(error: NativeSocialError): string {
  const name = error.provider ? socialProviderLabel(error.provider) : null;
  switch (error.code) {
    case 'apple_email_required':
      return "Apple didn't share a verified email, so OpenKey can't create an account from it. Sign in with your email or passkey, then add Apple in Settings.";
    case 'account_not_linked':
      return `An OpenKey account already uses this email. Sign in to it and add ${name ?? 'this sign-in method'} in Settings.`;
    case 'cancelled':
      return name ? `${name} sign-in was cancelled.` : 'Sign-in was cancelled.';
    default:
      return name ? `${name} could not complete sign-in. Please try again.` : 'Sign-in could not complete. Please try again.';
  }
}

/** Same shape rules the API applies to `login_hint`; anything else is ignored. */
export function nativeLoginHint(value: string | null | undefined): string | null {
  const hint = value?.trim() ?? '';
  if (!hint || hint.length > 254 || /\s/.test(hint)) return null;
  const parts = hint.split('@');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  return hint.toLowerCase();
}

/** Null unless the page's authorize query carries `tinycloud_request`. */
export function nativeSignIn(searchParams: URLSearchParams): NativeSignIn | null {
  const signedQuery = safeOAuthAuthorizeQuery(searchParams);
  if (!signedQuery) return null;
  const query = new URLSearchParams(signedQuery);
  const requestId = query.get('tinycloud_request');
  const clientId = query.get('client_id');
  if (!requestId || !clientId) return null;

  const rawMethod = query.get('login_method');
  const method = LOGIN_METHODS.find((candidate) => candidate === rawMethod) ?? null;
  const hint = nativeLoginHint(query.get('login_hint'));
  const emailHint = hint && (method === 'email' || method === null) ? hint : null;
  return {
    requestId,
    clientId,
    signedQuery,
    method: emailHint && !method ? 'email' : method,
    hint: emailHint,
    socialError: nativeSocialError(searchParams),
  };
}

/**
 * Where Better Auth returns after Google or Apple. Both land on the login page
 * with the signed authorize query so the page can re-enter /authorize; the
 * native query is never sent in the social sign-in body. The error return
 * names the provider so the page can say which one failed.
 */
export function nativeSocialReturnUrls(
  origin: string,
  signedQuery: string,
  provider: NativeSocialProvider,
): { callbackURL: string; errorCallbackURL: string } {
  const callbackURL = `${origin}/auth/login?${signedQuery}`;
  return { callbackURL, errorCallbackURL: `${callbackURL}&${NATIVE_SOCIAL_ERROR_PARAM}=${provider}` };
}

export function nativeOtpSentKey(requestId: string): string {
  return `openkey:native-otp-sent:${requestId}`;
}

export function nativeReentryKey(requestId: string): string {
  return `openkey:native-reentry:${requestId}`;
}

export interface NativeBranding {
  clientId: string;
  name: string;
  icon: string | null;
  organization: string | null;
  theme: { backgroundColor: string | null; accentColor: string | null };
}

function brandingText(value: unknown, max: number): string | null {
  return typeof value === 'string' && value.trim() && value.length <= max ? value : null;
}

export function parseNativeBranding(body: unknown, clientId: string): NativeBranding {
  const data = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
  const theme = (data.theme && typeof data.theme === 'object' ? data.theme : {}) as Record<string, unknown>;
  const name = brandingText(data.name, 100);
  if (!name) throw new Error('branding response has no name');
  return {
    clientId,
    name,
    icon: safeExternalHttpUrl(data.icon),
    organization: brandingText(data.organization, 100),
    theme: { backgroundColor: parseHexColor(theme.backgroundColor), accentColor: parseHexColor(theme.accentColor) },
  };
}

export async function loadNativeBranding(clientId: string, fetchImpl: typeof fetch = fetch): Promise<NativeBranding> {
  const response = await fetchImpl(
    `${API_BASE}/api/oauth/tinycloud/clients/${encodeURIComponent(clientId)}/branding`,
    { headers: { Accept: 'application/json' }, credentials: 'omit' },
  );
  if (!response.ok) throw new Error(`branding request failed (${response.status})`);
  return parseNativeBranding(await response.json(), clientId);
}
