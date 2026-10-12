import { safeOAuthAuthorizeQuery } from './auth-flow';
import { API_BASE } from './auth-client';
import { safeExternalHttpUrl } from './safe-oauth-url';
import { parseHexColor } from './native-theme';

export type NativeLoginMethod = 'email' | 'passkey' | 'google';

const LOGIN_METHODS: readonly NativeLoginMethod[] = ['email', 'passkey', 'google'];

/** Marker on the Google error return, and on "Not you?" to drop the signed hints. */
export const NATIVE_SOCIAL_ERROR_PARAM = 'native_social_error';
export const NATIVE_SWITCH_ACCOUNT_PARAM = 'native_switch';

export interface NativeSignIn {
  requestId: string;
  clientId: string;
  /** The signed authorize query, exactly as the API issued it. */
  signedQuery: string;
  method: NativeLoginMethod | null;
  hint: string | null;
  socialError: boolean;
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

  const switching = searchParams.has(NATIVE_SWITCH_ACCOUNT_PARAM);
  const rawMethod = query.get('login_method');
  const method = LOGIN_METHODS.find((candidate) => candidate === rawMethod) ?? null;
  const hint = nativeLoginHint(query.get('login_hint'));
  const emailHint = hint && (method === 'email' || method === null) ? hint : null;
  return {
    requestId,
    clientId,
    signedQuery,
    method: switching ? null : emailHint && !method ? 'email' : method,
    hint: switching ? null : emailHint,
    socialError: searchParams.has(NATIVE_SOCIAL_ERROR_PARAM),
  };
}

/**
 * Where Better Auth returns after Google. Both land on the login page with the
 * signed authorize query so the page can re-enter /authorize; the native query
 * is never sent in the social sign-in body.
 */
export function nativeSocialReturnUrls(origin: string, signedQuery: string): { callbackURL: string; errorCallbackURL: string } {
  const callbackURL = `${origin}/auth/login?${signedQuery}`;
  return { callbackURL, errorCallbackURL: `${callbackURL}&${NATIVE_SOCIAL_ERROR_PARAM}=1` };
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
