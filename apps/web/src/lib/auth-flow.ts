import { isConsolePath } from './console-host';

const OAUTH_AUTHORIZE_KEYS = new Set([
  'client_id',
  'redirect_uri',
  'response_type',
  'scope',
  'state',
  'code_challenge',
  'code_challenge_method',
  'nonce',
  'resource',
  'login_hint',
  'login_method',
  'max_age',
  'ui_locales',
  'claims',
  'prompt',
  'tinycloud_request',
  // @better-auth/oauth-provider signs the complete pre-login query and
  // rejects oauth_query on sign-in if any of this envelope is missing.
  'exp',
  'ba_iat',
  'ba_pl',
  'sig',
]);

const SAFE_RETURN_PREFIXES = [
  '/console',
  '/dashboard',
  '/delegate',
  '/oauth/',
  '/widget/',
];

type AuthReturnToOptions = {
  /** The separately hosted admin console is the sole allowed cross-origin return target. */
  consoleOrigin?: string;
};

export function normalizeAuthReturnTo(
  value: string | null | undefined,
  origin: string,
  allowedPrefixes: readonly string[] = SAFE_RETURN_PREFIXES,
  options: AuthReturnToOptions = {},
): string | null {
  if (!value) return null;
  if (value === '/org-registration/consent') return value;

  try {
    const url = new URL(value, origin);
    if (url.username || url.password) return null;
    const allowed = allowedPrefixes.some((prefix) =>
      prefix.endsWith('/')
        ? url.pathname.startsWith(prefix)
        : url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)
    );
    if (!allowed) return null;
    if (url.origin === origin) return `${url.pathname}${url.search}${url.hash}`;
    if (options.consoleOrigin && url.origin === options.consoleOrigin && isConsolePath(url.pathname)) {
      return url.href;
    }
    return null;
  } catch {
    return null;
  }
}

export function safeOAuthAuthorizeQuery(searchParams: URLSearchParams): string | undefined {
  const nestedQuery = searchParams.get('oauth_query');
  const source = nestedQuery ? new URLSearchParams(nestedQuery) : searchParams;
  if (!source.get('client_id')) return undefined;

  const safe = new URLSearchParams();
  for (const [key, value] of source) {
    if (OAUTH_AUTHORIZE_KEYS.has(key)) safe.append(key, value);
  }
  return safe.get('client_id') ? safe.toString() : undefined;
}

/**
 * In OAuth flows the API answers a sign-in with `{ redirect: true, url }`. The
 * auth client's redirect plugin would navigate in the same onSuccess pass, so
 * callers run this from their own onSuccess (which better-fetch runs first):
 * it clears the flag to veto that navigation and returns the URL to follow
 * once the page's own steps are done.
 */
export function holdOAuthRedirect(data: unknown): string | undefined {
  const answer = data as { redirect?: boolean; url?: unknown } | null;
  if (!answer?.redirect || typeof answer.url !== 'string' || !answer.url) return undefined;
  answer.redirect = false;
  return answer.url;
}
